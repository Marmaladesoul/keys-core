// Doc comments here use bare terms like `AutoFill`, `PSL`, `eTLD`,
// `URL` that read naturally in prose; backticking each occurrence
// would be noise. Same convention as engine_types.rs.
#![allow(clippy::doc_markdown)]

//! AutoFill domain matching.
//!
//! Given a service identifier (a URL or a bare host string from
//! `ASCredentialServiceIdentifier` on iOS/macOS, or the equivalent on
//! other platforms), produce a list of candidate domains from
//! most-specific to the registrable domain (eTLD+1 per the Mozilla
//! Public Suffix List).
//!
//! # Why PSL
//!
//! The macOS Swift implementation this port replaces shipped a
//! hardcoded set of ~80 multi-part TLDs (`com.au`, `co.uk`, etc.). That
//! list missed many legitimate public suffixes — anything under
//! `*.github.io`, `*.s3.amazonaws.com`, `*.cloudfront.net`, every
//! country-code eTLD not on the short list — and would silently produce
//! a *wrong* registrable domain in those cases, which for AutoFill
//! means matching credentials against the wrong site. Backing this
//! with the full Mozilla PSL (via the `psl` crate, compile-time-bundled)
//! eliminates the entire class of "TLD list isn't comprehensive enough"
//! correctness bug.
//!
//! # Algorithm
//!
//! 1. Normalise the identifier to a host string: parse as URL (adding
//!    `https://` if missing), lowercase, strip a leading `www.`.
//! 2. Look up the registrable domain via `psl::domain`.
//! 3. Walk leftmost labels off the host, emitting each intermediate
//!    form, until the registrable domain itself remains. If the input
//!    *is* a public suffix (no registrable), fall back to returning the
//!    host as-is.

use psl::Psl;
use url::Url;

/// Produce candidate domains from most-specific to the registrable
/// domain.
///
/// Returns an empty vector for inputs that cannot be parsed to a host.
#[must_use]
pub fn domain_candidates(service_identifier: &str) -> Vec<String> {
    let Some(host) = normalise_host(service_identifier) else {
        return Vec::new();
    };

    let registrable = registrable_domain(&host);

    let host_parts: Vec<&str> = host.split('.').collect();

    let Some(reg) = registrable else {
        return vec![host];
    };

    let reg_label_count = reg.split('.').count();

    let mut out = Vec::new();
    let mut start = 0usize;
    while host_parts.len() - start >= reg_label_count {
        out.push(host_parts[start..].join("."));
        if host_parts.len() - start == reg_label_count {
            break;
        }
        start += 1;
    }
    out
}

fn normalise_host(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = Url::parse(&with_scheme).ok()?;
    let host = parsed.host_str()?.to_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(
        host.strip_prefix("www.")
            .map_or_else(|| host.clone(), str::to_owned),
    )
}

/// The registrable domain (eTLD+1) for `host`, per the Mozilla PSL.
/// Returns `None` if the host *is* a public suffix (e.g. `com`,
/// `co.uk`, `github.io`).
fn registrable_domain(host: &str) -> Option<String> {
    let domain = psl::List.domain(host.as_bytes())?;
    std::str::from_utf8(domain.as_bytes())
        .ok()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_host_returns_self() {
        assert_eq!(domain_candidates("example.com"), vec!["example.com"]);
    }

    #[test]
    fn subdomain_walks_to_registrable() {
        assert_eq!(
            domain_candidates("dash.cloudflare.com"),
            vec!["dash.cloudflare.com", "cloudflare.com"]
        );
    }

    #[test]
    fn multi_part_tld_recognised() {
        assert_eq!(
            domain_candidates("shop.example.com.au"),
            vec!["shop.example.com.au", "example.com.au"]
        );
    }

    #[test]
    fn multi_part_tld_no_subdomain() {
        assert_eq!(domain_candidates("example.com.au"), vec!["example.com.au"]);
    }

    #[test]
    fn deep_subdomain_multi_part_tld() {
        assert_eq!(
            domain_candidates("a.b.c.example.co.uk"),
            vec![
                "a.b.c.example.co.uk",
                "b.c.example.co.uk",
                "c.example.co.uk",
                "example.co.uk",
            ]
        );
    }

    #[test]
    fn www_prefix_stripped() {
        assert_eq!(domain_candidates("www.example.com"), vec!["example.com"]);
    }

    #[test]
    fn url_identifier_parses_like_bare_host() {
        assert_eq!(
            domain_candidates("https://login.example.com/path?q=1"),
            vec!["login.example.com", "example.com"]
        );
    }

    #[test]
    fn empty_input_returns_empty() {
        assert!(domain_candidates("").is_empty());
    }

    #[test]
    fn whitespace_only_returns_empty() {
        assert!(domain_candidates("   ").is_empty());
    }

    // ────────────────────────────────────────────────────────────
    // PSL-backed cases the Swift hardcoded list could not handle.
    // ────────────────────────────────────────────────────────────

    /// `github.io` is a public suffix per the PSL. The registrable
    /// domain for `example.github.io` is therefore the full
    /// `example.github.io`, not `github.io`. AutoFill must not match
    /// credentials across two unrelated GitHub Pages sites.
    #[test]
    fn github_io_is_a_public_suffix() {
        assert_eq!(
            domain_candidates("example.github.io"),
            vec!["example.github.io"]
        );
        assert_eq!(
            domain_candidates("blog.example.github.io"),
            vec!["blog.example.github.io", "example.github.io"]
        );
    }

    /// `s3.amazonaws.com` is a public suffix. Each S3 bucket gets its
    /// own registrable domain.
    #[test]
    fn s3_amazonaws_is_a_public_suffix() {
        assert_eq!(
            domain_candidates("mybucket.s3.amazonaws.com"),
            vec!["mybucket.s3.amazonaws.com"]
        );
    }

    /// Public suffix itself collapses to just the host (no
    /// registrable). Matches Swift's behaviour for the same input.
    #[test]
    fn bare_public_suffix_returns_host() {
        assert_eq!(domain_candidates("co.uk"), vec!["co.uk"]);
    }

    /// Country-code TLD outside the Swift hardcoded list. Norway's
    /// `.no` is a normal eTLD; PSL handles it correctly.
    #[test]
    fn norway_tld() {
        assert_eq!(
            domain_candidates("forum.example.no"),
            vec!["forum.example.no", "example.no"]
        );
    }
}
