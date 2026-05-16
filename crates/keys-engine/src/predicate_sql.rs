//! Predicate-to-SQL compiler (task 3.6).
//!
//! Translates a [`Predicate`] tree into a parameterised SQL `WHERE`
//! fragment plus a vector of bind values. Task 3.8 will consume the
//! result to build `SELECT … FROM entry WHERE {where_sql} ORDER BY …`.
//!
//! ## Strictly parameterised
//!
//! Every user-supplied value goes through a `?` placeholder. No
//! `format!` interpolation of user data anywhere — that's SQL injection
//! territory. The only string concatenation is over fixed schema
//! identifiers and the compiler's own templates.
//!
//! ## LIKE-wildcard escaping
//!
//! Substring predicates ([`Predicate::TitleContains`] et al.) bind
//! `%user_input%`. To prevent a user's literal `%` or `_` from acting
//! as a wildcard, the user's input is escaped (`\`, `%`, `_` get a
//! backslash prefix) and the SQL is emitted with `LIKE ? ESCAPE '\'`.
//! Pragmatic call: users expressing wildcard
//! intent isn't a documented predicate feature, so we treat their
//! literals as literals. Mirrors the search path's LIKE escaping in
//! the `reads` module.
//!
//! ## Unknown variants
//!
//! [`Predicate::Unknown`] has no SQL image; the compiler refuses with
//! [`CompileError::NotEvaluable`]. Task 3.8 should check
//! [`Predicate::is_evaluable`] before calling.
//!
//! ## Empty And / Or / Tag-set
//!
//! Empty `And` / `Or` lists and empty `TagHasAny` / `TagHasAll` lists
//! return [`CompileError::EmptyAndOr`] rather than silently producing
//! a `1=1` or `0=1` SQL literal. Callers should validate inputs at
//! authoring time.

use rusqlite::types::Value;

use crate::predicate::Predicate;

/// A predicate compiled into a parameterised SQL `WHERE` fragment.
///
/// `where_sql` is a self-contained boolean expression wrapped in
/// parentheses so it composes safely under outer `AND` / `OR`. `params`
/// is the matching list of bind values, in the order the `?`
/// placeholders appear.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledPredicate {
    /// SQL boolean expression. Always parenthesised.
    pub where_sql: String,
    /// Bind values, in placeholder order.
    pub params: Vec<Value>,
}

/// Failure modes for [`compile`].
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompileError {
    /// The predicate tree contains a [`Predicate::Unknown`] node and
    /// therefore has no SQL image. Callers should check
    /// [`Predicate::is_evaluable`] before compiling.
    #[error("predicate contains an Unknown variant; tree is not evaluable")]
    NotEvaluable,

    /// An `And` / `Or` / `TagHasAny` / `TagHasAll` node has no
    /// children. The compiler refuses rather than emit `1=1` / `0=1`
    /// silently.
    #[error("empty And/Or/Tag-set: predicate has no children")]
    EmptyAndOr,
}

/// Compile a [`Predicate`] tree into a parameterised SQL fragment.
///
/// `now_ms` is the wall-clock reference point used by time-relative
/// predicates ([`Predicate::ModifiedWithin`],
/// [`Predicate::ExpiringWithin`], [`Predicate::Expired`]). Callers
/// pass `SystemTime::now()` at evaluation time; tests pass a fixed
/// value for determinism.
///
/// # Errors
///
/// - [`CompileError::NotEvaluable`] if the tree contains a
///   [`Predicate::Unknown`] node anywhere.
/// - [`CompileError::EmptyAndOr`] if an `And` / `Or` / `TagHasAny`
///   / `TagHasAll` node has no children.
pub fn compile(predicate: &Predicate, now_ms: i64) -> Result<CompiledPredicate, CompileError> {
    match predicate {
        Predicate::And { predicates } => compile_junction(predicates, "AND", now_ms),
        Predicate::Or { predicates } => compile_junction(predicates, "OR", now_ms),
        Predicate::Not { predicate } => {
            let inner = compile(predicate, now_ms)?;
            Ok(CompiledPredicate {
                where_sql: format!("(NOT {})", inner.where_sql),
                params: inner.params,
            })
        }
        Predicate::TitleContains { substring } => Ok(like_contains("entry.title", substring)),
        Predicate::UrlContains { substring } => Ok(like_contains("entry.url", substring)),
        Predicate::UsernameContains { substring } => Ok(like_contains("entry.username", substring)),
        Predicate::UrlHostEquals { host } => Ok(CompiledPredicate {
            where_sql: "(entry.url_host = ?)".into(),
            params: vec![Value::Text(host.clone())],
        }),
        Predicate::TagEquals { tag } => Ok(CompiledPredicate {
            where_sql: tag_exists_sql(),
            params: vec![Value::Text(tag.clone())],
        }),
        Predicate::TagHasAny { tags } => {
            if tags.is_empty() {
                return Err(CompileError::EmptyAndOr);
            }
            let placeholders = vec!["?"; tags.len()].join(", ");
            let where_sql = format!(
                "(EXISTS (SELECT 1 FROM entry_tag \
                    JOIN tag ON entry_tag.tag_id = tag.id \
                    WHERE entry_tag.entry_uuid = entry.uuid AND tag.name IN ({placeholders})))"
            );
            Ok(CompiledPredicate {
                where_sql,
                params: tags.iter().cloned().map(Value::Text).collect(),
            })
        }
        Predicate::TagHasAll { tags } => {
            if tags.is_empty() {
                return Err(CompileError::EmptyAndOr);
            }
            let exists = tag_exists_sql();
            let parts: Vec<String> = (0..tags.len()).map(|_| exists.clone()).collect();
            let where_sql = format!("({})", parts.join(" AND "));
            Ok(CompiledPredicate {
                where_sql,
                params: tags.iter().cloned().map(Value::Text).collect(),
            })
        }
        Predicate::ModifiedWithin { duration } => {
            let cutoff = now_ms.saturating_sub(duration_ms(*duration));
            Ok(CompiledPredicate {
                where_sql: "(entry.modified_at >= ?)".into(),
                params: vec![Value::Integer(cutoff)],
            })
        }
        Predicate::ModifiedBefore { timestamp_ms } => Ok(CompiledPredicate {
            where_sql: "(entry.modified_at < ?)".into(),
            params: vec![Value::Integer(*timestamp_ms)],
        }),
        Predicate::Expired => Ok(CompiledPredicate {
            where_sql: "(entry.expires_at IS NOT NULL AND entry.expires_at < ?)".into(),
            params: vec![Value::Integer(now_ms)],
        }),
        Predicate::ExpiringWithin { duration } => {
            let upper = now_ms.saturating_add(duration_ms(*duration));
            Ok(CompiledPredicate {
                where_sql: "(entry.expires_at IS NOT NULL \
                             AND entry.expires_at >= ? \
                             AND entry.expires_at <= ?)"
                    .into(),
                params: vec![Value::Integer(now_ms), Value::Integer(upper)],
            })
        }
        Predicate::StrengthBelow { bucket } => Ok(CompiledPredicate {
            where_sql: "(entry.password_strength_bucket IS NOT NULL \
                         AND entry.password_strength_bucket < ?)"
                .into(),
            params: vec![Value::Integer(i64::from(*bucket as u8))],
        }),
        Predicate::EntropyBelow { bits } => Ok(CompiledPredicate {
            where_sql: "(entry.password_entropy IS NOT NULL AND entry.password_entropy < ?)".into(),
            params: vec![Value::Real(*bits)],
        }),
        Predicate::Duplicates => Ok(CompiledPredicate {
            where_sql: "(entry.password_fingerprint IS NOT NULL \
                         AND entry.password_fingerprint IN ( \
                             SELECT password_fingerprint FROM entry \
                             WHERE password_fingerprint IS NOT NULL \
                             GROUP BY password_fingerprint \
                             HAVING COUNT(*) > 1))"
                .into(),
            params: vec![],
        }),
        Predicate::Group { uuid } => Ok(CompiledPredicate {
            where_sql: "(entry.group_uuid = ?)".into(),
            params: vec![Value::Text(uuid.to_string())],
        }),
        Predicate::Unknown(_) => Err(CompileError::NotEvaluable),
    }
}

fn compile_junction(
    children: &[Predicate],
    op: &str,
    now_ms: i64,
) -> Result<CompiledPredicate, CompileError> {
    if children.is_empty() {
        return Err(CompileError::EmptyAndOr);
    }
    let mut parts = Vec::with_capacity(children.len());
    let mut params = Vec::new();
    for child in children {
        let c = compile(child, now_ms)?;
        parts.push(c.where_sql);
        params.extend(c.params);
    }
    let joined = parts.join(&format!(" {op} "));
    Ok(CompiledPredicate {
        where_sql: format!("({joined})"),
        params,
    })
}

fn like_contains(column: &str, substring: &str) -> CompiledPredicate {
    let escaped = escape_like(substring);
    CompiledPredicate {
        where_sql: format!("({column} LIKE ? ESCAPE '\\')"),
        params: vec![Value::Text(format!("%{escaped}%"))],
    }
}

fn tag_exists_sql() -> String {
    "(EXISTS (SELECT 1 FROM entry_tag \
        JOIN tag ON entry_tag.tag_id = tag.id \
        WHERE entry_tag.entry_uuid = entry.uuid AND tag.name = ?))"
        .to_string()
}

/// Escape `\`, `%`, `_` so they're treated as literals inside a
/// `LIKE ? ESCAPE '\'` pattern.
fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Convert a [`std::time::Duration`] into milliseconds, saturating
/// to [`i64::MAX`] for absurd durations rather than panicking.
fn duration_ms(d: std::time::Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use uuid::Uuid;

    use super::*;
    use crate::model::StrengthBucket;

    const NOW: i64 = 1_700_000_000_000;

    fn text(s: &str) -> Value {
        Value::Text(s.to_string())
    }

    #[test]
    fn compile_title_contains() {
        let p = Predicate::TitleContains {
            substring: "bank".into(),
        };
        let c = compile(&p, NOW).expect("compile");
        assert_eq!(c.where_sql, "(entry.title LIKE ? ESCAPE '\\')");
        assert_eq!(c.params, vec![text("%bank%")]);
    }

    #[test]
    fn compile_url_contains_escapes_wildcards() {
        let p = Predicate::UrlContains {
            substring: "%test_".into(),
        };
        let c = compile(&p, NOW).expect("compile");
        assert_eq!(c.where_sql, "(entry.url LIKE ? ESCAPE '\\')");
        assert_eq!(c.params, vec![text("%\\%test\\_%")]);
    }

    #[test]
    fn compile_username_contains() {
        let p = Predicate::UsernameContains {
            substring: "alice".into(),
        };
        let c = compile(&p, NOW).expect("compile");
        assert_eq!(c.where_sql, "(entry.username LIKE ? ESCAPE '\\')");
        assert_eq!(c.params, vec![text("%alice%")]);
    }

    #[test]
    fn compile_url_host_equals() {
        let p = Predicate::UrlHostEquals {
            host: "github.com".into(),
        };
        let c = compile(&p, NOW).expect("compile");
        assert_eq!(c.where_sql, "(entry.url_host = ?)");
        assert_eq!(c.params, vec![text("github.com")]);
    }

    #[test]
    fn compile_tag_equals() {
        let p = Predicate::TagEquals {
            tag: "banking".into(),
        };
        let c = compile(&p, NOW).expect("compile");
        assert!(c.where_sql.contains("EXISTS"));
        assert!(c.where_sql.contains("tag.name = ?"));
        assert_eq!(c.params, vec![text("banking")]);
    }

    #[test]
    fn compile_tag_has_any() {
        let p = Predicate::TagHasAny {
            tags: vec!["a".into(), "b".into(), "c".into()],
        };
        let c = compile(&p, NOW).expect("compile");
        assert!(c.where_sql.contains("tag.name IN (?, ?, ?)"));
        assert_eq!(c.params, vec![text("a"), text("b"), text("c")]);
    }

    #[test]
    fn compile_tag_has_all_two_tags() {
        let p = Predicate::TagHasAll {
            tags: vec!["x".into(), "y".into()],
        };
        let c = compile(&p, NOW).expect("compile");
        // Two EXISTS clauses ANDed.
        let exists_count = c.where_sql.matches("EXISTS").count();
        assert_eq!(exists_count, 2);
        assert!(c.where_sql.contains(" AND "));
        assert_eq!(c.params, vec![text("x"), text("y")]);
    }

    #[test]
    fn compile_modified_within_uses_now_minus_duration() {
        let p = Predicate::ModifiedWithin {
            duration: Duration::from_secs(60),
        };
        let c = compile(&p, NOW).expect("compile");
        assert_eq!(c.where_sql, "(entry.modified_at >= ?)");
        assert_eq!(c.params, vec![Value::Integer(NOW - 60_000)]);
    }

    #[test]
    fn compile_modified_before() {
        let p = Predicate::ModifiedBefore {
            timestamp_ms: 123_456,
        };
        let c = compile(&p, NOW).expect("compile");
        assert_eq!(c.where_sql, "(entry.modified_at < ?)");
        assert_eq!(c.params, vec![Value::Integer(123_456)]);
    }

    #[test]
    fn compile_expired() {
        let c = compile(&Predicate::Expired, NOW).expect("compile");
        assert_eq!(
            c.where_sql,
            "(entry.expires_at IS NOT NULL AND entry.expires_at < ?)"
        );
        assert_eq!(c.params, vec![Value::Integer(NOW)]);
    }

    #[test]
    fn compile_expiring_within() {
        let p = Predicate::ExpiringWithin {
            duration: Duration::from_secs(86_400),
        };
        let c = compile(&p, NOW).expect("compile");
        assert!(c.where_sql.contains("expires_at IS NOT NULL"));
        assert!(c.where_sql.contains(">= ?"));
        assert!(c.where_sql.contains("<= ?"));
        assert_eq!(
            c.params,
            vec![Value::Integer(NOW), Value::Integer(NOW + 86_400_000)]
        );
    }

    #[test]
    fn compile_strength_below() {
        let p = Predicate::StrengthBelow {
            bucket: StrengthBucket::Reasonable,
        };
        let c = compile(&p, NOW).expect("compile");
        assert!(c.where_sql.contains("password_strength_bucket"));
        assert!(c.where_sql.contains("< ?"));
        assert_eq!(c.params, vec![Value::Integer(2)]);
    }

    #[test]
    fn compile_entropy_below() {
        let p = Predicate::EntropyBelow { bits: 40.0 };
        let c = compile(&p, NOW).expect("compile");
        assert!(c.where_sql.contains("password_entropy"));
        assert_eq!(c.params, vec![Value::Real(40.0)]);
    }

    #[test]
    fn compile_duplicates() {
        let c = compile(&Predicate::Duplicates, NOW).expect("compile");
        assert!(c.where_sql.contains("password_fingerprint IN"));
        assert!(c.where_sql.contains("COUNT(*) > 1"));
        assert!(c.params.is_empty());
    }

    #[test]
    fn compile_group() {
        let uuid = Uuid::nil();
        let c = compile(&Predicate::Group { uuid }, NOW).expect("compile");
        assert_eq!(c.where_sql, "(entry.group_uuid = ?)");
        assert_eq!(c.params, vec![text(&uuid.to_string())]);
    }

    #[test]
    fn compile_and_recursive() {
        let p = Predicate::And {
            predicates: vec![
                Predicate::TitleContains {
                    substring: "foo".into(),
                },
                Predicate::TagEquals { tag: "t".into() },
            ],
        };
        let c = compile(&p, NOW).expect("compile");
        assert!(c.where_sql.starts_with('('));
        assert!(c.where_sql.contains(" AND "));
        assert!(c.where_sql.contains("entry.title LIKE"));
        assert!(c.where_sql.contains("EXISTS"));
        assert_eq!(c.params, vec![text("%foo%"), text("t")]);
    }

    #[test]
    fn compile_or_recursive() {
        let p = Predicate::Or {
            predicates: vec![Predicate::Expired, Predicate::Duplicates],
        };
        let c = compile(&p, NOW).expect("compile");
        assert!(c.where_sql.contains(" OR "));
        assert_eq!(c.params, vec![Value::Integer(NOW)]);
    }

    #[test]
    fn compile_not_negates() {
        let p = Predicate::Not {
            predicate: Box::new(Predicate::Expired),
        };
        let c = compile(&p, NOW).expect("compile");
        assert!(c.where_sql.starts_with("(NOT "));
        assert_eq!(c.params, vec![Value::Integer(NOW)]);
    }

    #[test]
    fn compile_unknown_returns_not_evaluable_error() {
        let p = Predicate::Unknown(serde_json::json!({"type": "future"}));
        assert_eq!(compile(&p, NOW), Err(CompileError::NotEvaluable));
    }

    #[test]
    fn compile_not_containing_unknown_propagates_error() {
        let p = Predicate::Not {
            predicate: Box::new(Predicate::Unknown(serde_json::json!({"type": "future"}))),
        };
        assert_eq!(compile(&p, NOW), Err(CompileError::NotEvaluable));
    }

    #[test]
    fn compile_and_containing_unknown_propagates_error() {
        let p = Predicate::And {
            predicates: vec![
                Predicate::Expired,
                Predicate::Unknown(serde_json::json!({"type": "future"})),
            ],
        };
        assert_eq!(compile(&p, NOW), Err(CompileError::NotEvaluable));
    }

    #[test]
    fn compile_empty_and_returns_error() {
        let p = Predicate::And { predicates: vec![] };
        assert_eq!(compile(&p, NOW), Err(CompileError::EmptyAndOr));
    }

    #[test]
    fn compile_empty_or_returns_error() {
        let p = Predicate::Or { predicates: vec![] };
        assert_eq!(compile(&p, NOW), Err(CompileError::EmptyAndOr));
    }

    #[test]
    fn compile_empty_tag_has_any_returns_error() {
        let p = Predicate::TagHasAny { tags: vec![] };
        assert_eq!(compile(&p, NOW), Err(CompileError::EmptyAndOr));
    }

    #[test]
    fn compile_empty_tag_has_all_returns_error() {
        let p = Predicate::TagHasAll { tags: vec![] };
        assert_eq!(compile(&p, NOW), Err(CompileError::EmptyAndOr));
    }

    #[test]
    fn escape_like_handles_special_chars() {
        assert_eq!(escape_like("plain"), "plain");
        assert_eq!(escape_like("50%"), "50\\%");
        assert_eq!(escape_like("a_b"), "a\\_b");
        assert_eq!(escape_like("c\\d"), "c\\\\d");
    }
}
