//! Smart-folder predicate AST.
//!
//! Predicates are serialised to JSON and stored in the `smart_folder`
//! table. Frontends can produce and consume them; the engine compiles
//! them to parameterised SQL via the (not-yet-written) Phase 3.6
//! compiler.
//!
//! # JSON shape
//!
//! Tagged-union encoding: every node carries a `"type"` discriminator
//! in `snake_case` plus its variant-specific fields. Example:
//!
//! ```json
//! {
//!     "type": "and",
//!     "predicates": [
//!         { "type": "tag_equals", "tag": "banking" },
//!         { "type": "modified_within", "duration_secs": 604800 }
//!     ]
//! }
//! ```
//!
//! # Versioning
//!
//! Per the four versioning rules in `SQLITE_MIGRATION.md`:
//!
//! 1. **Tagged unions.** Every variant has a stable `type` string.
//! 2. **Additive-only producers.** New variants and new optional
//!    fields are non-breaking. Removing or renaming is a wire break.
//! 3. **Tolerant decoders.** Unknown `type` discriminators map to the
//!    [`Predicate::Unknown`] catch-all variant rather than failing the
//!    whole document. The enclosing smart-folder document marks
//!    itself non-evaluable when an `Unknown` appears anywhere in its
//!    tree — that wiring lives in Phase 3.9.
//! 4. **Top-level `version` field** on the folder document for
//!    emergency wholesale restructures.
//!
//! # `Unknown` catch-all
//!
//! Task description offered two options: `#[serde(other)]` unit
//! variant or `serde_json::Value` payload. Phase 3.9 will need to
//! preserve the raw JSON so a future-version decoder can re-evaluate
//! the folder; today's `#[serde(other)]` unit variant **does not**
//! preserve raw JSON — the unknown-type field bag is discarded.
//!
//! Choice: ship the unit-variant `#[serde(other)]` form here as the
//! minimum viable tolerant decoder. Task 3.9 swaps in a
//! `Value`-preserving variant (likely via a custom `Deserialize` impl,
//! since `#[serde(other)]` is unit-only on tagged unions). Cross-ref
//! is `SQLITE_MIGRATION.md` Phase 3.9.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::StrengthBucket;

/// Smart-folder predicate AST.
///
/// `#[non_exhaustive]` so adding variants is non-breaking for downstream
/// `match` users (they get a compile error pointing them at the new
/// variant) but `Predicate { … }` exhaustive matches in other crates
/// remain forward-compatible after a wildcard arm is added.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Predicate {
    /// Logical AND of nested predicates.
    And {
        /// Predicates that must all match.
        predicates: Vec<Predicate>,
    },
    /// Logical OR of nested predicates.
    Or {
        /// Predicates of which at least one must match.
        predicates: Vec<Predicate>,
    },
    /// Logical NOT of a nested predicate.
    Not {
        /// Predicate to negate.
        predicate: Box<Predicate>,
    },
    /// Entry title contains the given substring (case-insensitive).
    TitleContains {
        /// Substring to match.
        substring: String,
    },
    /// Entry URL contains the given substring (case-insensitive).
    UrlContains {
        /// Substring to match.
        substring: String,
    },
    /// Entry username contains the given substring (case-insensitive).
    UsernameContains {
        /// Substring to match.
        substring: String,
    },
    /// Entry URL host equals the given value (case-insensitive,
    /// matches the indexed `url_host` column).
    UrlHostEquals {
        /// Host to match (e.g. `"github.com"`).
        host: String,
    },
    /// Entry has the given tag.
    TagEquals {
        /// Tag to look for.
        tag: String,
    },
    /// Entry has any of the given tags.
    TagHasAny {
        /// Tags; match succeeds if the entry has at least one.
        tags: Vec<String>,
    },
    /// Entry has all of the given tags.
    TagHasAll {
        /// Tags; match succeeds only if the entry has every one.
        tags: Vec<String>,
    },
    /// Entry was modified within the given duration before "now".
    ///
    /// Stored as integer seconds in JSON for human readability and
    /// cross-platform safety (avoiding `Duration`'s nanos field).
    ModifiedWithin {
        /// Window length in seconds.
        #[serde(with = "duration_secs")]
        duration: Duration,
    },
    /// Entry was modified before the given timestamp.
    ModifiedBefore {
        /// Cutoff timestamp, ms since Unix epoch (UTC).
        timestamp_ms: i64,
    },
    /// Entry has an expiry date in the past.
    Expired,
    /// Entry expires within the given duration after "now".
    ExpiringWithin {
        /// Window length in seconds.
        #[serde(with = "duration_secs")]
        duration: Duration,
    },
    /// Entry's password strength bucket is strictly below the given threshold.
    StrengthBelow {
        /// Threshold bucket (e.g. `Reasonable` selects `VeryWeak` + `Weak`).
        bucket: StrengthBucket,
    },
    /// Entry's password entropy is strictly below the given bit count.
    EntropyBelow {
        /// Threshold in bits.
        bits: f64,
    },
    /// Entry's password fingerprint matches at least one other entry's.
    Duplicates,
    /// Entry is in the given group.
    Group {
        /// Group UUID.
        uuid: Uuid,
    },
    /// Catch-all for unknown discriminator values, per versioning rule 3.
    ///
    /// `#[serde(other)]` requires the variant to be unit-shaped; the
    /// payload of unrecognised JSON is therefore discarded. Phase 3.9
    /// replaces this with a `Value`-preserving variant via a custom
    /// `Deserialize` impl. Until then, smart folders containing an
    /// unknown predicate are non-evaluable but the surrounding
    /// document still decodes.
    #[serde(other)]
    Unknown,
}

/// Serde adapter encoding [`Duration`] as integer seconds.
mod duration_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_union_round_trip() {
        let p = Predicate::And {
            predicates: vec![
                Predicate::TagEquals {
                    tag: "banking".into(),
                },
                Predicate::ModifiedWithin {
                    duration: Duration::from_secs(86_400 * 7),
                },
            ],
        };

        let json = serde_json::to_value(&p).expect("serialise");
        // Confirm tagged-union shape.
        assert_eq!(json["type"], "and");
        assert_eq!(json["predicates"][0]["type"], "tag_equals");
        assert_eq!(json["predicates"][0]["tag"], "banking");
        assert_eq!(json["predicates"][1]["type"], "modified_within");
        assert_eq!(json["predicates"][1]["duration"], 86_400 * 7);

        let round_tripped: Predicate = serde_json::from_value(json).expect("deserialise");
        assert_eq!(round_tripped, p);
    }

    #[test]
    fn unknown_discriminator_maps_to_unknown_variant() {
        let raw = serde_json::json!({ "type": "future_variant_v2", "data": 42 });
        let decoded: Predicate = serde_json::from_value(raw).expect("tolerant decode");
        assert_eq!(decoded, Predicate::Unknown);
    }
}
