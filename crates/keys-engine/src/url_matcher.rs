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
//! 1. Normalise the identifier to a host: parse as URL (adding
//!    `https://` if missing), lowercase, strip a leading `www.`, and
//!    reject hosts with an empty label (`example..com`, a bare `www.`).
//!    An IP literal is kept whole — the PSL's wildcard rule would
//!    otherwise read the last octet as a TLD and peel `192.168.1.1`
//!    down to `1.1`.
//! 2. Look up the registrable domain via `psl::domain`.
//! 3. Walk leftmost labels off the host, emitting each intermediate
//!    form, until the registrable domain itself remains. If the input
//!    *is* a public suffix (no registrable), fall back to returning the
//!    host as-is.
//!
//! [`credential_domain`] is the registration-side twin of
//! [`domain_candidates`]: the one domain a credential for the identifier
//! should be filed under, so that a store keyed on it and a lookup that
//! walks the candidates agree by construction. [`origin`] is the
//! save-side companion: the URL a credential saved from the identifier's
//! page records, which keys on the same host.

use psl::Psl;
use url::Url;

/// Produce candidate domains from most-specific to the registrable
/// domain.
///
/// Returns an empty vector for inputs that cannot be parsed to a host.
/// An IP literal has no labels to walk and is returned alone.
#[must_use]
pub fn domain_candidates(service_identifier: &str) -> Vec<String> {
    let host = match normalise_host(service_identifier) {
        None => return Vec::new(),
        Some(Host::Ip(ip)) => return vec![ip],
        Some(Host::Domain(host)) => host,
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

/// The one domain a credential for `service_identifier` should be
/// registered under, such that a lookup walking [`domain_candidates`]
/// for any page on the same site reaches it:
///
/// - a host with a registrable domain → that domain (`login.example.com`
///   and `shop.example.com.au` file under `example.com` and
///   `example.com.au`; a hosted tenant such as `blog.example.github.io`
///   under `example.github.io`, never the shared `github.io`);
/// - an IP literal or a single-label host (`192.168.1.1`, `localhost`,
///   `nas`) → itself, since there is nothing coarser and no other site
///   it could be confused with;
/// - a multi-label public suffix (`github.io`, `co.uk`) → `None`: a
///   credential filed there would be offered to every tenant beneath
///   it, so there is no safe domain to register;
/// - anything with no derivable host → `None`.
#[must_use]
pub fn credential_domain(service_identifier: &str) -> Option<String> {
    match normalise_host(service_identifier)? {
        Host::Ip(ip) => Some(ip),
        Host::Domain(host) => {
            if let Some(registrable) = registrable_domain(&host) {
                Some(registrable)
            } else if host.contains('.') {
                None
            } else {
                Some(host)
            }
        }
    }
}

/// The origin (`scheme://host[:port]`) of the page `service_identifier`
/// names: the URL a credential saved from that page should record.
///
/// Scheme and port are the page's own, so an `http://` intranet page or
/// a dev server on `:8765` saves as exactly that rather than as
/// `https://` on the default port; a bare host (no scheme) reads as
/// `https://`. The path, query, fragment and any user-info are dropped:
/// a login page's path is incidental, a query can carry session tokens,
/// and every lookup keys on the host alone. Serialisation is the WHATWG
/// origin's: lower-cased host, default port omitted, IDN hosts in
/// punycode, IPv6 bracketed.
///
/// `None` when [`domain_candidates`] would find no host (blank,
/// unparseable, or an empty label such as a trailing dot), or when the
/// scheme has no tuple origin (`file:`, custom schemes). By
/// construction the origin keys on the same host as the identifier, so
/// [`domain_candidates`] and [`credential_domain`] give the same answer
/// for both.
#[must_use]
pub fn origin(service_identifier: &str) -> Option<String> {
    let parsed = parse_with_default_scheme(service_identifier)?;
    site_host(&parsed)?;
    let origin = parsed.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// A normalised service-identifier host. IP literals are kept apart
/// because label-walking and public-suffix lookups are meaningless on
/// them (and actively wrong under the PSL's wildcard rule).
enum Host {
    Domain(String),
    Ip(String),
}

fn normalise_host(s: &str) -> Option<Host> {
    site_host(&parse_with_default_scheme(s)?)
}

/// The site host of a parsed identifier: lower-cased, `www.` stripped,
/// IP literals kept whole; `None` when it names no site.
fn site_host(parsed: &Url) -> Option<Host> {
    let host = match parsed.host()? {
        url::Host::Ipv4(ip) => return Some(Host::Ip(ip.to_string())),
        url::Host::Ipv6(ip) => return Some(Host::Ip(ip.to_string())),
        url::Host::Domain(domain) => domain.to_lowercase(),
    };
    let host = host.strip_prefix("www.").unwrap_or(&host);
    // `url` accepts `example..com` and a bare `www.`; neither names a
    // site, and a public-suffix lookup on them yields `.com` or ``.
    if host.is_empty() || host.split('.').any(str::is_empty) {
        return None;
    }
    Some(Host::Domain(host.to_owned()))
}

/// Parse a service identifier as a URL, reading a bare host
/// (`example.com`) as `https://example.com`.
fn parse_with_default_scheme(s: &str) -> Option<Url> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains("://") {
        Url::parse(trimmed).ok()
    } else {
        Url::parse(&format!("https://{trimmed}")).ok()
    }
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
        let got = domain_candidates("");
        assert!(got.is_empty(), "got {got:?}");
    }

    #[test]
    fn whitespace_only_returns_empty() {
        let got = domain_candidates("   ");
        assert!(got.is_empty(), "got {got:?}");
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

    /// The PSL's wildcard rule would read `1` as a TLD and walk
    /// `192.168.1.1` down to `1.1`; an IP literal is one host, not a
    /// label tree.
    #[test]
    fn ip_literal_is_a_single_candidate() {
        assert_eq!(
            domain_candidates("https://192.168.1.1/admin"),
            vec!["192.168.1.1"]
        );
        assert_eq!(domain_candidates("10.0.0.1"), vec!["10.0.0.1"]);
        assert_eq!(domain_candidates("https://[::1]:8443/"), vec!["::1"]);
    }

    /// `url` parses these, but no site has an empty label; a suffix
    /// lookup on them would yield `.com` or an empty string.
    #[test]
    fn empty_labels_are_not_a_host() {
        let got = domain_candidates("https://example..com");
        assert!(got.is_empty(), "got {got:?}");
        let got = domain_candidates("www.");
        assert!(got.is_empty(), "got {got:?}");
        let got = domain_candidates("https://www./login");
        assert!(got.is_empty(), "got {got:?}");
    }

    #[test]
    fn hosts_are_lowercased() {
        assert_eq!(
            domain_candidates("https://Login.Example.COM"),
            vec!["login.example.com", "example.com"]
        );
    }

    // ────────────────────────────────────────────────────────────
    // credential_domain — the registration-side twin.
    // ────────────────────────────────────────────────────────────

    /// The registered domain is always the last candidate, so a lookup
    /// that walks the candidates for any page on the site reaches it.
    #[test]
    fn credential_domain_is_the_last_candidate_for_registrable_hosts() {
        for id in [
            "example.com",
            "https://login.example.com/path?q=1",
            "https://WWW.Example.Com",
            "shop.example.com.au",
            "a.b.c.example.co.uk",
            "blog.example.github.io",
            "mybucket.s3.amazonaws.com",
            "forum.example.no",
            "192.168.1.1",
            "localhost",
        ] {
            assert_eq!(
                credential_domain(id),
                domain_candidates(id).last().cloned(),
                "{id}"
            );
        }
    }

    #[test]
    fn credential_domain_collapses_to_registrable() {
        assert_eq!(
            credential_domain("https://login.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            credential_domain("https://Shop.Example.COM.AU/cart").as_deref(),
            Some("example.com.au")
        );
        assert_eq!(
            credential_domain("blog.example.github.io").as_deref(),
            Some("example.github.io")
        );
    }

    /// IPs and single-label hosts are their own domain: there is no
    /// coarser form, and nothing else they could be confused with.
    #[test]
    fn credential_domain_keeps_ips_and_single_labels_whole() {
        assert_eq!(
            credential_domain("https://192.168.1.1/admin").as_deref(),
            Some("192.168.1.1")
        );
        assert_eq!(
            credential_domain("https://[fe80::1]/").as_deref(),
            Some("fe80::1")
        );
        assert_eq!(
            credential_domain("localhost:8080").as_deref(),
            Some("localhost")
        );
        assert_eq!(credential_domain("https://nas/").as_deref(), Some("nas"));
    }

    /// A multi-label public suffix has no registrable domain and would
    /// match every tenant beneath it; there is nothing safe to register.
    #[test]
    fn credential_domain_refuses_multi_label_public_suffixes() {
        assert_eq!(credential_domain("https://github.io"), None);
        assert_eq!(credential_domain("co.uk"), None);
        assert_eq!(credential_domain("s3.amazonaws.com"), None);
    }

    #[test]
    fn credential_domain_is_none_without_a_host() {
        assert_eq!(credential_domain(""), None);
        assert_eq!(credential_domain("not a url"), None);
        assert_eq!(credential_domain("https://example..com"), None);
        assert_eq!(credential_domain("www."), None);
    }

    // ────────────────────────────────────────────────────────────
    // origin — the URL a credential saved from the page records.
    // ────────────────────────────────────────────────────────────

    /// The page's scheme and port survive; path, query and fragment go.
    #[test]
    fn origin_keeps_scheme_and_port() {
        assert_eq!(
            origin("http://localhost:8765/login.html").as_deref(),
            Some("http://localhost:8765")
        );
        assert_eq!(
            origin("https://dash.cloudflare.com/login?next=/home#x").as_deref(),
            Some("https://dash.cloudflare.com")
        );
    }

    /// A bare host has no scheme to keep and reads as https.
    #[test]
    fn origin_of_bare_host_is_https() {
        assert_eq!(
            origin("example.com").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            origin("localhost:8080").as_deref(),
            Some("https://localhost:8080")
        );
    }

    #[test]
    fn origin_of_ip_literals() {
        assert_eq!(
            origin("http://192.168.1.1:8080/admin").as_deref(),
            Some("http://192.168.1.1:8080")
        );
        assert_eq!(
            origin("http://[::1]:8080/").as_deref(),
            Some("http://[::1]:8080")
        );
    }

    /// WHATWG serialisation: host lower-cased, the scheme's default port
    /// dropped, user-info never carried over, `www.` kept (it is the
    /// page's real host).
    #[test]
    fn origin_is_canonical() {
        assert_eq!(
            origin("HTTPS://user:secret@WWW.Example.COM:443/").as_deref(),
            Some("https://www.example.com")
        );
        assert_eq!(
            origin("http://example.com:80/").as_deref(),
            Some("http://example.com")
        );
    }

    #[test]
    fn origin_is_none_without_a_web_host() {
        assert_eq!(origin(""), None);
        assert_eq!(origin("not a url"), None);
        assert_eq!(origin("https://example.com./"), None);
        assert_eq!(origin("https://example..com"), None);
        assert_eq!(origin("file:///etc/passwd"), None);
    }

    /// Saving the origin must not change which domain the store and the
    /// lookup walk key on.
    #[test]
    fn origin_keys_on_the_same_domains_as_the_page() {
        for page in [
            "http://localhost:8765/login.html",
            "https://www.login.example.com/path?q=1",
            "https://shop.example.com.au/cart",
            "http://192.168.1.1:8080/admin",
            "http://[::1]:8080/",
            "example.com",
        ] {
            let saved = origin(page).unwrap_or_else(|| panic!("no origin for {page}"));
            assert_eq!(domain_candidates(&saved), domain_candidates(page), "{page}");
            assert_eq!(credential_domain(&saved), credential_domain(page), "{page}");
        }
    }
}
