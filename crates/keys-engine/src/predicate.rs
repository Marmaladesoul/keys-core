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
//!    whole document. The raw JSON object is preserved so a future
//!    binary that recognises the discriminator can re-evaluate the
//!    folder. The enclosing smart-folder row stores `evaluable = 0`
//!    whenever any node in its tree is `Unknown` —
//!    [`Predicate::is_evaluable`] is the in-process check.
//! 4. **Top-level `version` field** on the folder document for
//!    emergency wholesale restructures.
//!
//! # `Unknown` catch-all
//!
//! Carries the raw [`serde_json::Value`] of the offending node so it
//! survives round-trips through the database verbatim. A future
//! binary that learns the discriminator can re-deserialise the
//! preserved JSON and re-evaluate the folder without the user
//! needing to re-author it.
//!
//! Implementation note: `serde`'s tagged-union derive doesn't support
//! a non-unit `#[serde(other)]` variant, so the `Serialize` /
//! `Deserialize` impls below are hand-rolled. The known variants
//! still come from a private derive-built enum (`KnownPredicate`) so
//! adding a variant remains a one-line change to the public enum +
//! one line in the conversion helpers.

use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use uuid::Uuid;

use crate::model::StrengthBucket;

/// Smart-folder predicate AST.
///
/// `#[non_exhaustive]` so adding variants is non-breaking for downstream
/// `match` users (they get a compile error pointing them at the new
/// variant) but `Predicate { … }` exhaustive matches in other crates
/// remain forward-compatible after a wildcard arm is added.
#[derive(Debug, Clone, PartialEq)]
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
    /// Carries the raw JSON object so a future-version binary that
    /// recognises the discriminator can read the original payload
    /// without the user re-authoring the smart folder. The enclosing
    /// folder is marked `evaluable = 0` whenever this variant appears
    /// anywhere in the tree.
    Unknown(serde_json::Value),
}

impl Predicate {
    /// Recursively check whether this predicate tree is evaluable.
    ///
    /// Returns `false` if any node anywhere in the tree is
    /// [`Predicate::Unknown`], otherwise `true`. Used by:
    ///
    /// - [`crate::Engine::create_smart_folder`] /
    ///   [`crate::Engine::update_smart_folder`] to compute the
    ///   `evaluable` column on insert/update;
    /// - the upcoming SQL compiler (3.6) to refuse to compile an
    ///   unknown variant;
    /// - smart-folder evaluation (3.8) to short-circuit before
    ///   touching the SQL layer.
    #[must_use]
    pub fn is_evaluable(&self) -> bool {
        match self {
            Self::Unknown(_) => false,
            Self::And { predicates } | Self::Or { predicates } => {
                predicates.iter().all(Self::is_evaluable)
            }
            Self::Not { predicate } => predicate.is_evaluable(),
            _ => true,
        }
    }
}

// ── Serialisation ───────────────────────────────────────────────────────
//
// Hand-rolled because `serde`'s `#[serde(tag = "type", other)]` requires
// the catch-all variant to be unit-shaped, but we want to preserve the
// raw JSON of the unknown node. The trick: define a private mirror enum
// that covers only the known variants and uses the derive macro, then
// dispatch to it from the public enum's manual impls.

/// Private mirror of [`Predicate`] minus the [`Predicate::Unknown`]
/// arm. Serde's derive handles the tagged-union shape; the public
/// impls below convert in and out.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum KnownPredicate {
    And {
        predicates: Vec<Predicate>,
    },
    Or {
        predicates: Vec<Predicate>,
    },
    Not {
        predicate: Box<Predicate>,
    },
    TitleContains {
        substring: String,
    },
    UrlContains {
        substring: String,
    },
    UsernameContains {
        substring: String,
    },
    UrlHostEquals {
        host: String,
    },
    TagEquals {
        tag: String,
    },
    TagHasAny {
        tags: Vec<String>,
    },
    TagHasAll {
        tags: Vec<String>,
    },
    ModifiedWithin {
        #[serde(with = "duration_secs")]
        duration: Duration,
    },
    ModifiedBefore {
        timestamp_ms: i64,
    },
    Expired,
    ExpiringWithin {
        #[serde(with = "duration_secs")]
        duration: Duration,
    },
    StrengthBelow {
        bucket: StrengthBucket,
    },
    EntropyBelow {
        bits: f64,
    },
    Duplicates,
    Group {
        uuid: Uuid,
    },
}

impl From<KnownPredicate> for Predicate {
    fn from(value: KnownPredicate) -> Self {
        match value {
            KnownPredicate::And { predicates } => Self::And { predicates },
            KnownPredicate::Or { predicates } => Self::Or { predicates },
            KnownPredicate::Not { predicate } => Self::Not { predicate },
            KnownPredicate::TitleContains { substring } => Self::TitleContains { substring },
            KnownPredicate::UrlContains { substring } => Self::UrlContains { substring },
            KnownPredicate::UsernameContains { substring } => Self::UsernameContains { substring },
            KnownPredicate::UrlHostEquals { host } => Self::UrlHostEquals { host },
            KnownPredicate::TagEquals { tag } => Self::TagEquals { tag },
            KnownPredicate::TagHasAny { tags } => Self::TagHasAny { tags },
            KnownPredicate::TagHasAll { tags } => Self::TagHasAll { tags },
            KnownPredicate::ModifiedWithin { duration } => Self::ModifiedWithin { duration },
            KnownPredicate::ModifiedBefore { timestamp_ms } => {
                Self::ModifiedBefore { timestamp_ms }
            }
            KnownPredicate::Expired => Self::Expired,
            KnownPredicate::ExpiringWithin { duration } => Self::ExpiringWithin { duration },
            KnownPredicate::StrengthBelow { bucket } => Self::StrengthBelow { bucket },
            KnownPredicate::EntropyBelow { bits } => Self::EntropyBelow { bits },
            KnownPredicate::Duplicates => Self::Duplicates,
            KnownPredicate::Group { uuid } => Self::Group { uuid },
        }
    }
}

impl Predicate {
    /// Mirror of `Into<KnownPredicate>` but fallible: the
    /// [`Predicate::Unknown`] arm has no [`KnownPredicate`] image.
    /// Returns `None` for `Unknown(_)`.
    fn as_known(&self) -> Option<KnownPredicate> {
        Some(match self {
            Self::And { predicates } => KnownPredicate::And {
                predicates: predicates.clone(),
            },
            Self::Or { predicates } => KnownPredicate::Or {
                predicates: predicates.clone(),
            },
            Self::Not { predicate } => KnownPredicate::Not {
                predicate: predicate.clone(),
            },
            Self::TitleContains { substring } => KnownPredicate::TitleContains {
                substring: substring.clone(),
            },
            Self::UrlContains { substring } => KnownPredicate::UrlContains {
                substring: substring.clone(),
            },
            Self::UsernameContains { substring } => KnownPredicate::UsernameContains {
                substring: substring.clone(),
            },
            Self::UrlHostEquals { host } => KnownPredicate::UrlHostEquals { host: host.clone() },
            Self::TagEquals { tag } => KnownPredicate::TagEquals { tag: tag.clone() },
            Self::TagHasAny { tags } => KnownPredicate::TagHasAny { tags: tags.clone() },
            Self::TagHasAll { tags } => KnownPredicate::TagHasAll { tags: tags.clone() },
            Self::ModifiedWithin { duration } => KnownPredicate::ModifiedWithin {
                duration: *duration,
            },
            Self::ModifiedBefore { timestamp_ms } => KnownPredicate::ModifiedBefore {
                timestamp_ms: *timestamp_ms,
            },
            Self::Expired => KnownPredicate::Expired,
            Self::ExpiringWithin { duration } => KnownPredicate::ExpiringWithin {
                duration: *duration,
            },
            Self::StrengthBelow { bucket } => KnownPredicate::StrengthBelow { bucket: *bucket },
            Self::EntropyBelow { bits } => KnownPredicate::EntropyBelow { bits: *bits },
            Self::Duplicates => KnownPredicate::Duplicates,
            Self::Group { uuid } => KnownPredicate::Group { uuid: *uuid },
            Self::Unknown(_) => return None,
        })
    }
}

impl Serialize for Predicate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Self::Unknown(value) = self {
            // Re-emit the preserved JSON verbatim.
            value.serialize(serializer)
        } else {
            // `as_known` returns `Some` for all non-Unknown variants.
            self.as_known()
                .expect("non-Unknown variants always convert")
                .serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Predicate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // First decode into a generic Value so we can both try the
        // known-variant decode and keep the raw bytes for `Unknown`.
        let value = serde_json::Value::deserialize(deserializer)?;
        match serde_json::from_value::<KnownPredicate>(value.clone()) {
            Ok(known) => Ok(known.into()),
            Err(known_err) => {
                // Only swallow the failure if the cause is an
                // unrecognised `type` discriminator. Malformed JSON
                // for a *known* variant (e.g. `tag_equals` without
                // `tag`) is still a hard decode error — silently
                // mapping that to `Unknown` would hide real producer
                // bugs.
                if is_unknown_type_error(&value) {
                    Ok(Self::Unknown(value))
                } else {
                    Err(DeError::custom(known_err))
                }
            }
        }
    }
}

/// Inspect the raw [`serde_json::Value`] to decide whether a failed
/// `KnownPredicate` decode was caused by an unrecognised `type`
/// discriminator (tolerable, per rule 3) or by a malformed payload
/// for an otherwise-known type (hard error).
fn is_unknown_type_error(value: &serde_json::Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    let Some(type_str) = obj.get("type").and_then(serde_json::Value::as_str) else {
        return false;
    };
    !KNOWN_TYPE_DISCRIMINATORS.contains(&type_str)
}

/// Canonical list of `type` discriminators that [`KnownPredicate`]
/// recognises. Keep in lock-step with the variant list above —
/// `every_known_variant_round_trips` exercises every entry, so a
/// mismatch surfaces at test time.
const KNOWN_TYPE_DISCRIMINATORS: &[&str] = &[
    "and",
    "or",
    "not",
    "title_contains",
    "url_contains",
    "username_contains",
    "url_host_equals",
    "tag_equals",
    "tag_has_any",
    "tag_has_all",
    "modified_within",
    "modified_before",
    "expired",
    "expiring_within",
    "strength_below",
    "entropy_below",
    "duplicates",
    "group",
];

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

    fn round_trip(p: &Predicate) -> Predicate {
        let json = serde_json::to_value(p).expect("serialise");
        serde_json::from_value(json).expect("deserialise")
    }

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
        assert_eq!(json["type"], "and");
        assert_eq!(json["predicates"][0]["type"], "tag_equals");
        assert_eq!(json["predicates"][0]["tag"], "banking");
        assert_eq!(json["predicates"][1]["type"], "modified_within");
        assert_eq!(json["predicates"][1]["duration"], 86_400 * 7);

        let round_tripped: Predicate = serde_json::from_value(json).expect("deserialise");
        assert_eq!(round_tripped, p);
    }

    #[test]
    fn every_known_variant_round_trips() {
        let group_uuid = Uuid::nil();
        let variants = vec![
            Predicate::And {
                predicates: vec![Predicate::Expired],
            },
            Predicate::Or {
                predicates: vec![Predicate::Duplicates],
            },
            Predicate::Not {
                predicate: Box::new(Predicate::Expired),
            },
            Predicate::TitleContains {
                substring: "foo".into(),
            },
            Predicate::UrlContains {
                substring: "example.com".into(),
            },
            Predicate::UsernameContains {
                substring: "alice".into(),
            },
            Predicate::UrlHostEquals {
                host: "github.com".into(),
            },
            Predicate::TagEquals {
                tag: "banking".into(),
            },
            Predicate::TagHasAny {
                tags: vec!["a".into(), "b".into()],
            },
            Predicate::TagHasAll {
                tags: vec!["x".into(), "y".into()],
            },
            Predicate::ModifiedWithin {
                duration: Duration::from_secs(60),
            },
            Predicate::ModifiedBefore {
                timestamp_ms: 1_700_000_000_000,
            },
            Predicate::Expired,
            Predicate::ExpiringWithin {
                duration: Duration::from_secs(86_400 * 30),
            },
            Predicate::StrengthBelow {
                bucket: StrengthBucket::Reasonable,
            },
            Predicate::EntropyBelow { bits: 40.0 },
            Predicate::Duplicates,
            Predicate::Group { uuid: group_uuid },
        ];
        for p in &variants {
            assert_eq!(round_trip(p), *p, "round-trip differs for {p:?}");
        }
    }

    #[test]
    fn is_evaluable_simple_returns_true() {
        let cases = [
            Predicate::Expired,
            Predicate::Duplicates,
            Predicate::TitleContains {
                substring: "x".into(),
            },
            Predicate::EntropyBelow { bits: 10.0 },
            Predicate::TagHasAll {
                tags: vec!["a".into()],
            },
            Predicate::ModifiedWithin {
                duration: Duration::from_secs(1),
            },
        ];
        for p in &cases {
            assert!(p.is_evaluable(), "expected evaluable: {p:?}");
        }
    }

    #[test]
    fn is_evaluable_unknown_returns_false() {
        let p = Predicate::Unknown(serde_json::json!({"type": "future_v2"}));
        assert!(!p.is_evaluable());
    }

    #[test]
    fn is_evaluable_recursive() {
        let with_unknown = Predicate::And {
            predicates: vec![
                Predicate::Expired,
                Predicate::Unknown(serde_json::json!({"type": "future"})),
            ],
        };
        assert!(!with_unknown.is_evaluable());

        let nested_unknown = Predicate::Or {
            predicates: vec![Predicate::Not {
                predicate: Box::new(Predicate::Unknown(serde_json::json!({"type": "future"}))),
            }],
        };
        assert!(!nested_unknown.is_evaluable());

        let all_known = Predicate::Or {
            predicates: vec![
                Predicate::Expired,
                Predicate::And {
                    predicates: vec![Predicate::Duplicates],
                },
            ],
        };
        assert!(all_known.is_evaluable());
    }

    #[test]
    fn unknown_discriminator_maps_to_unknown_variant() {
        let raw = serde_json::json!({ "type": "future_variant_v2", "data": 42 });
        let decoded: Predicate = serde_json::from_value(raw.clone()).expect("tolerant decode");
        assert_eq!(decoded, Predicate::Unknown(raw));
    }

    #[test]
    fn unknown_preserves_raw_json() {
        let raw = serde_json::json!({
            "type": "fancy_new_predicate",
            "extra": "data",
            "nested": { "deep": [1, 2, 3] }
        });
        let decoded: Predicate = serde_json::from_value(raw.clone()).expect("decode");
        let Predicate::Unknown(ref preserved) = decoded else {
            panic!("expected Unknown, got {decoded:?}");
        };
        assert_eq!(preserved, &raw);

        // Re-encode then re-decode → same blob.
        let re_encoded = serde_json::to_value(&decoded).expect("re-encode");
        assert_eq!(re_encoded, raw);
        let re_decoded: Predicate = serde_json::from_value(re_encoded).expect("re-decode");
        assert_eq!(re_decoded, decoded);
    }

    #[test]
    fn malformed_known_variant_is_hard_error() {
        // `tag_equals` is known but is missing the required `tag` field.
        // This must not silently become `Unknown` — that would hide
        // genuine producer bugs.
        let raw = serde_json::json!({ "type": "tag_equals" });
        let result: Result<Predicate, _> = serde_json::from_value(raw);
        assert!(result.is_err(), "expected hard error, got {result:?}");
    }
}
