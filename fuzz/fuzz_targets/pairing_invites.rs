//! Fuzz target for the invite book: arbitrary sequences of issuing,
//! knocking, retiring, storing, restoring and the clock moving, checked
//! against a model that is nothing but the rules.
//!
//! The rules (see `keys_pairing::invite`): a knock is answered as open only
//! for an invite that is in the book and not expired, and only for the
//! first endpoint that knocked on it; that endpoint is told "first time"
//! exactly once; an invite's opener never changes; an expired invite never
//! comes back, and a retired one only if the client restores a record of
//! it from before; no invite is issued for longer than the longest
//! lifetime; the book never holds more than its cap.
//!
//! Each input byte pair is one operation. Random bytes are scripted from
//! the input, so a crash replays from its artefact.

#![no_main]

use libfuzzer_sys::fuzz_target;

use keys_pairing::invite::{
    InviteBook, InviteRecord, MAX_INVITE_LIFETIME_SECS, MAX_OUTSTANDING_INVITES,
};
use keys_pairing::{InviteId, KnockOutcome, PairingAddress};

const START: u64 = 1_800_000_000;
const HOUR: u64 = 60 * 60;
/// Hours of lifetime per unit of an issue's argument: the largest argument
/// asks for more than the longest lifetime allowed.
const LIFETIME_STEP_HOURS: u64 = 4;
const _: () = assert!(255 * LIFETIME_STEP_HOURS * HOUR > MAX_INVITE_LIFETIME_SECS);
const ISSUER: [u8; 32] = [0x15; 32];
const IDENTITY: [u8; 32] = [0xa1; 32];
/// How many endpoints knock. Few, so they collide on invites.
const KNOCKERS: u8 = 3;
/// An id no book issued (the scripted stream never produces a constant).
const UNKNOWN: InviteId = [0x99; 16];

/// What the rules say about one invite.
struct Expected {
    id: InviteId,
    expires_at: u64,
    opened_by: Option<[u8; 32]>,
    retired: bool,
}

impl Expected {
    fn outstanding(&self, now: u64) -> bool {
        !self.retired && now < self.expires_at
    }
}

fuzz_target!(|data: &[u8]| {
    keys_pairing::script_random_for_fuzzing(data);
    let mut book = InviteBook::new();
    let mut expected: Vec<Expected> = Vec::new();
    let mut stored: Vec<InviteRecord> = Vec::new();
    let mut now = START;
    // An invite that was ever seen expired stays gone, whatever the clock
    // does later, so the model's clock only moves forward too.
    for pair in data.chunks_exact(2) {
        let (op, arg) = (pair[0] % 8, pair[1]);
        match op {
            0 => {
                let lifetime = u64::from(arg) * LIFETIME_STEP_HOURS * HOUR;
                let allowed = lifetime > 0 && lifetime <= MAX_INVITE_LIFETIME_SECS;
                let address = PairingAddress::new(ISSUER, None).expect("no relay to refuse");
                let outstanding = expected.iter().filter(|e| e.outstanding(now)).count();
                match book.issue(IDENTITY, address, "", lifetime, now) {
                    Ok(invite) => {
                        assert!(allowed, "issued an invite with a lifetime out of bounds");
                        assert!(outstanding < MAX_OUTSTANDING_INVITES, "issued past the cap");
                        assert_eq!(invite.expires_at, now + lifetime);
                        assert!(
                            expected.iter().all(|e| e.id != invite.invite_id),
                            "an invite id came up twice"
                        );
                        expected.push(Expected {
                            id: invite.invite_id,
                            expires_at: invite.expires_at,
                            opened_by: None,
                            retired: false,
                        });
                    }
                    Err(_) => assert!(
                        !allowed || outstanding >= MAX_OUTSTANDING_INVITES,
                        "refused an invite the rules allow"
                    ),
                }
            }
            1 | 2 => {
                let knocker = [arg % KNOCKERS; 32];
                let which = usize::from(arg / KNOCKERS);
                let Some(invite) = expected.get_mut(which) else {
                    assert_eq!(
                        book.answer_knock(&UNKNOWN, knocker, now),
                        KnockOutcome::NotOutstanding,
                        "an invite nobody issued was answered as open"
                    );
                    continue;
                };
                let outcome = book.answer_knock(&invite.id, knocker, now);
                let want = if !invite.outstanding(now) {
                    KnockOutcome::NotOutstanding
                } else {
                    match invite.opened_by {
                        None => {
                            invite.opened_by = Some(knocker);
                            KnockOutcome::Opened { first_time: true }
                        }
                        Some(opener) if opener == knocker => {
                            KnockOutcome::Opened { first_time: false }
                        }
                        Some(_) => KnockOutcome::NotOutstanding,
                    }
                };
                assert_eq!(outcome, want, "a knock answered against the rules");
            }
            3 => {
                let Some(invite) = expected.get_mut(usize::from(arg)) else {
                    continue;
                };
                assert_eq!(
                    book.retire(&invite.id, now),
                    invite.outstanding(now),
                    "retire disagreed about what was outstanding"
                );
                invite.retired = true;
            }
            4 => now += u64::from(arg) * HOUR,
            5 => stored = book.records(now),
            6 => {
                // A store that was altered, or written while the clock was
                // far ahead: a record that expires later than any invite
                // issued now could. It never gets into the book.
                let altered = InviteRecord {
                    invite_id: UNKNOWN,
                    expires_at: now + MAX_INVITE_LIFETIME_SECS + 1 + u64::from(arg) * HOUR,
                    opened_by: None,
                };
                assert!(
                    book.restore(altered, now).is_err(),
                    "restored an invite that outlasts the longest lifetime"
                );
            }
            _ => {
                // A relaunch: a new book, given back what was last stored.
                // What was issued or opened since then is lost with the old
                // book, exactly as it would be.
                book = InviteBook::new();
                for invite in &mut expected {
                    match stored.iter().find(|record| record.invite_id == invite.id) {
                        // As it was when stored, a later retirement
                        // included: the store is the client's to keep
                        // current.
                        Some(record) => {
                            invite.opened_by = record.opened_by;
                            invite.retired = false;
                        }
                        None => invite.retired = true,
                    }
                }
                for record in &stored {
                    let known = expected
                        .iter()
                        .find(|e| e.id == record.invite_id)
                        .expect("only issued invites are stored");
                    assert_eq!(
                        book.restore(*record, now).is_ok(),
                        known.outstanding(now),
                        "restore disagreed about what was outstanding"
                    );
                }
            }
        }

        // After every step the book holds exactly what the rules say.
        let mut held = book.records(now);
        held.sort_by_key(|record| record.invite_id);
        let mut want: Vec<InviteRecord> = expected
            .iter()
            .filter(|e| e.outstanding(now))
            .map(|e| InviteRecord {
                invite_id: e.id,
                expires_at: e.expires_at,
                opened_by: e.opened_by,
            })
            .collect();
        want.sort_by_key(|record| record.invite_id);
        assert_eq!(held, want, "the book and the rules disagree");
        assert!(
            held.len() <= MAX_OUTSTANDING_INVITES,
            "the book is over its cap"
        );
    }
});
