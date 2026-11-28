//! Person invites, and the book of the ones a device has issued.
//!
//! An invite is how one person's device tells another's where to find it. It
//! carries public values only: the inviter's account identity key, the
//! issuing device's [`PairingAddress`], a single-use invite id, an expiry
//! and the inviter's own name for themself. It holds no key that opens
//! anything and is not authenticated: whoever carries it can change it. What
//! the person verifies is the code, afterwards.
//!
//! When the other person opens the invite their device knocks on the issuing
//! device, naming the invite id. The [`InviteBook`] decides the answer:
//!
//! - **Only an outstanding invite is answered as open.** An id this book
//!   never issued, a retired one and an expired one all get the same
//!   answer, so a knock can't tell them apart.
//! - **The first endpoint to knock is the invite's opener.** The same
//!   endpoint may knock again (its first answer may have been lost) and
//!   hears the same thing. Any other endpoint is told the invite isn't
//!   outstanding. Someone who got hold of the invite and knocked first locks
//!   the invited person out, which fails safe: the code is still to come,
//!   and the invited person sees an invite that didn't work.
//! - **A knock runs no exchange and moves nothing.** It records which
//!   endpoint opened the invite, which is what the inviter's devices later
//!   dial to verify. That record is a dial hint set by an unauthenticated
//!   first-comer: it authorises nothing, and isn't evidence of who opened
//!   the invite.
//!
//! **Nothing in an invite is confirmed by the pairing that follows.** The
//! exchange doesn't cover the invite. Its identity key narrows what the
//! opener's sheet accepts; its name, expiry and address are as
//! unauthenticated after a successful pairing as before. Don't keep an
//! invite's name as the verified contact's name.
//!
//! The book lives in memory. A client that wants its invites to survive a
//! relaunch keeps each [`InviteRecord`] wherever it keeps its account data
//! and hands them back with [`InviteBook::restore`].
//!
//! Expiry is by the wall clock, in seconds since the Unix epoch, because an
//! invite outlives the process and crosses machines. A device whose clock is
//! wrong keeps an invite for too long or too short a time; all that rides on
//! it is whether a knock is recorded.

use crate::address::{MAX_DISPLAY_NAME_CHARS, PairingAddress, sanitize_display_name};
use crate::keys::PUBLIC_KEY_BYTES;
use crate::{EndpointId, PairingError};

/// Length of an invite id.
pub const INVITE_ID_BYTES: usize = 16;
/// The longest an invite may stay outstanding: thirty days.
pub const MAX_INVITE_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
/// How many invites one book holds at once. Issuing is the person's act, so
/// this only stops a runaway caller growing the book without end.
pub const MAX_OUTSTANDING_INVITES: usize = 64;
/// The longest a sanitised name is in UTF-8: every character four bytes.
pub(crate) const MAX_DISPLAY_NAME_BYTES: usize = MAX_DISPLAY_NAME_CHARS * 4;

/// A single-use invite id: 128 random bits. It names an invite; it is not a
/// secret, since it travels in the invite.
pub type InviteId = [u8; INVITE_ID_BYTES];

/// An invite to pair as People.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The account identity key the inviter says is theirs. Unverified
    /// until the pairing: the opener's sheet expects this key and refuses
    /// any other.
    pub inviter_identity: [u8; PUBLIC_KEY_BYTES],
    /// The device that issued the invite, and hears its knock.
    pub address: PairingAddress,
    pub invite_id: InviteId,
    /// Seconds since the Unix epoch.
    pub expires_at: u64,
    /// The inviter's name for themself, already sanitised. Chosen by
    /// whoever made the invite, and not confirmed by a pairing: show it as
    /// a claim, never as fact, and don't keep it as the contact's name.
    pub inviter_name: String,
}

impl Invite {
    /// Whether the invite's time is up at `now` (seconds since the Unix
    /// epoch).
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// Why an invite couldn't be issued or restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    /// The lifetime is zero or longer than [`MAX_INVITE_LIFETIME_SECS`], the
    /// expiry is past what the clock can count, or a restored record expires
    /// further off than that limit allows.
    #[error("an invite lasts between one second and thirty days")]
    Lifetime,
    /// The book already holds [`MAX_OUTSTANDING_INVITES`].
    #[error("too many invites are outstanding")]
    TooManyOutstanding,
    /// A restored record's id is already in the book.
    #[error("that invite is already in the book")]
    Duplicate,
    /// A restored record has already expired.
    #[error("that invite has expired")]
    Expired,
}

/// An issued invite as a client stores it between launches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteRecord {
    pub invite_id: InviteId,
    /// Seconds since the Unix epoch.
    pub expires_at: u64,
    /// The endpoint that opened the invite, once one has.
    pub opened_by: Option<EndpointId>,
}

/// The answer to a knock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnockOutcome {
    /// The invite is outstanding and this endpoint is its opener.
    /// `first_time` is false when the same endpoint had knocked before.
    Opened { first_time: bool },
    /// Nothing to open: never issued here, retired, expired, or already
    /// opened by another endpoint. One answer for all four.
    NotOutstanding,
}

/// The invites a device has issued and not yet retired.
#[derive(Debug, Default)]
pub struct InviteBook {
    records: Vec<InviteRecord>,
}

impl InviteBook {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn forget_expired(&mut self, now: u64) {
        self.records.retain(|record| now < record.expires_at);
    }

    fn position(&self, invite_id: &InviteId) -> Option<usize> {
        self.records
            .iter()
            .position(|record| &record.invite_id == invite_id)
    }

    /// Issues an invite from the account whose identity key is
    /// `inviter_identity`, to be answered at `address`, lasting
    /// `lifetime_secs` from `now`.
    ///
    /// # Errors
    /// [`InviteError::Lifetime`] or [`InviteError::TooManyOutstanding`], as
    /// those say, or [`PairingError::Random`] if the system random source
    /// fails. Nothing is added to the book on an error.
    pub fn issue(
        &mut self,
        inviter_identity: [u8; PUBLIC_KEY_BYTES],
        address: PairingAddress,
        inviter_name: &str,
        lifetime_secs: u64,
        now: u64,
    ) -> Result<Invite, IssueError> {
        if lifetime_secs == 0 || lifetime_secs > MAX_INVITE_LIFETIME_SECS {
            return Err(InviteError::Lifetime.into());
        }
        let expires_at = now
            .checked_add(lifetime_secs)
            .ok_or(InviteError::Lifetime)?;
        self.forget_expired(now);
        if self.records.len() >= MAX_OUTSTANDING_INVITES {
            return Err(InviteError::TooManyOutstanding.into());
        }
        let mut invite_id = [0u8; INVITE_ID_BYTES];
        crate::random::fill(&mut invite_id).map_err(|_| PairingError::Random)?;
        self.records.push(InviteRecord {
            invite_id,
            expires_at,
            opened_by: None,
        });
        Ok(Invite {
            inviter_identity,
            address,
            invite_id,
            expires_at,
            inviter_name: sanitize_display_name(inviter_name),
        })
    }

    /// Puts back an invite issued in an earlier launch.
    ///
    /// # Errors
    /// [`InviteError::Expired`]; [`InviteError::Lifetime`] for an expiry
    /// further off than any invite issued now could have (a store that was
    /// altered, or written while the clock was far ahead, can't keep an
    /// invite alive past the limit); [`InviteError::Duplicate`];
    /// [`InviteError::TooManyOutstanding`].
    pub fn restore(&mut self, record: InviteRecord, now: u64) -> Result<(), InviteError> {
        if now >= record.expires_at {
            return Err(InviteError::Expired);
        }
        if record.expires_at - now > MAX_INVITE_LIFETIME_SECS {
            return Err(InviteError::Lifetime);
        }
        self.forget_expired(now);
        if self.position(&record.invite_id).is_some() {
            return Err(InviteError::Duplicate);
        }
        if self.records.len() >= MAX_OUTSTANDING_INVITES {
            return Err(InviteError::TooManyOutstanding);
        }
        self.records.push(record);
        Ok(())
    }

    /// Answers a knock on `invite_id` from the endpoint `opener`, as the
    /// transport authenticated it, and records the opener if this is the
    /// invite's first knock.
    pub fn answer_knock(
        &mut self,
        invite_id: &InviteId,
        opener: EndpointId,
        now: u64,
    ) -> KnockOutcome {
        self.forget_expired(now);
        let Some(index) = self.position(invite_id) else {
            return KnockOutcome::NotOutstanding;
        };
        let record = &mut self.records[index];
        match record.opened_by {
            None => {
                record.opened_by = Some(opener);
                KnockOutcome::Opened { first_time: true }
            }
            Some(first) if first == opener => KnockOutcome::Opened { first_time: false },
            Some(_) => KnockOutcome::NotOutstanding,
        }
    }

    /// Retires an invite: it was cancelled, or its verification ended (in a
    /// pairing or on the dead end). Returns whether it was outstanding.
    pub fn retire(&mut self, invite_id: &InviteId, now: u64) -> bool {
        self.forget_expired(now);
        match self.position(invite_id) {
            Some(index) => {
                self.records.swap_remove(index);
                true
            }
            None => false,
        }
    }

    /// The outstanding invite with this id, if there is one.
    pub fn record(&mut self, invite_id: &InviteId, now: u64) -> Option<InviteRecord> {
        self.forget_expired(now);
        self.position(invite_id).map(|index| self.records[index])
    }

    /// Every outstanding invite, for a client to store.
    pub fn records(&mut self, now: u64) -> Vec<InviteRecord> {
        self.forget_expired(now);
        self.records.clone()
    }
}

/// Why [`InviteBook::issue`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IssueError {
    #[error(transparent)]
    Invite(#[from] InviteError),
    #[error(transparent)]
    Pairing(#[from] PairingError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::scripted;

    const IDENTITY: [u8; PUBLIC_KEY_BYTES] = [0xa1; PUBLIC_KEY_BYTES];
    const ISSUER: EndpointId = [0x15; 32];
    const OPENER: EndpointId = [0x0b; 32];
    const OTHER: EndpointId = [0x0c; 32];
    const NOW: u64 = 1_800_000_000;
    const WEEK: u64 = 7 * 24 * 60 * 60;

    fn address() -> PairingAddress {
        PairingAddress::new(ISSUER, Some("https://relay.example./".into())).unwrap()
    }

    fn issue(book: &mut InviteBook) -> Invite {
        book.issue(IDENTITY, address(), "Jeff", WEEK, NOW).unwrap()
    }

    #[test]
    fn an_issued_invite_carries_what_it_was_given_and_a_fresh_id() {
        let mut book = InviteBook::new();
        let first = issue(&mut book);
        let second = issue(&mut book);
        assert_eq!(first.inviter_identity, IDENTITY);
        assert_eq!(first.address, address());
        assert_eq!(first.expires_at, NOW + WEEK);
        assert_eq!(first.inviter_name, "Jeff");
        assert_ne!(first.invite_id, second.invite_id);
        assert!(!first.is_expired(NOW + WEEK - 1));
        assert!(first.is_expired(NOW + WEEK));
    }

    #[test]
    fn the_name_in_an_invite_is_sanitised() {
        let mut book = InviteBook::new();
        let invite = book
            .issue(IDENTITY, address(), " Jeff\u{202e}\n", WEEK, NOW)
            .unwrap();
        assert_eq!(invite.inviter_name, "Jeff");
    }

    #[test]
    fn a_lifetime_must_be_between_a_second_and_the_maximum() {
        let mut book = InviteBook::new();
        for bad in [0, MAX_INVITE_LIFETIME_SECS + 1, u64::MAX] {
            assert_eq!(
                book.issue(IDENTITY, address(), "", bad, NOW),
                Err(InviteError::Lifetime.into())
            );
        }
        assert_eq!(
            book.issue(IDENTITY, address(), "", 1, u64::MAX),
            Err(InviteError::Lifetime.into())
        );
        book.issue(IDENTITY, address(), "", MAX_INVITE_LIFETIME_SECS, NOW)
            .unwrap();
        assert_eq!(book.records(NOW).len(), 1);
    }

    #[test]
    fn the_first_knock_opens_and_the_same_endpoint_may_knock_again() {
        let mut book = InviteBook::new();
        let invite = issue(&mut book);
        assert_eq!(
            book.answer_knock(&invite.invite_id, OPENER, NOW),
            KnockOutcome::Opened { first_time: true }
        );
        assert_eq!(
            book.answer_knock(&invite.invite_id, OPENER, NOW + 1),
            KnockOutcome::Opened { first_time: false }
        );
        assert_eq!(
            book.record(&invite.invite_id, NOW).unwrap().opened_by,
            Some(OPENER)
        );
    }

    #[test]
    fn a_second_endpoint_is_told_nothing_is_outstanding_and_changes_nothing() {
        let mut book = InviteBook::new();
        let invite = issue(&mut book);
        book.answer_knock(&invite.invite_id, OPENER, NOW);
        assert_eq!(
            book.answer_knock(&invite.invite_id, OTHER, NOW),
            KnockOutcome::NotOutstanding
        );
        assert_eq!(
            book.record(&invite.invite_id, NOW).unwrap().opened_by,
            Some(OPENER)
        );
    }

    #[test]
    fn unknown_retired_and_expired_invites_all_answer_alike() {
        let mut book = InviteBook::new();
        assert_eq!(
            book.answer_knock(&[0x99; INVITE_ID_BYTES], OPENER, NOW),
            KnockOutcome::NotOutstanding
        );

        let retired = issue(&mut book);
        assert!(book.retire(&retired.invite_id, NOW));
        assert!(!book.retire(&retired.invite_id, NOW));
        assert_eq!(
            book.answer_knock(&retired.invite_id, OPENER, NOW),
            KnockOutcome::NotOutstanding
        );

        let expiring = issue(&mut book);
        assert_eq!(
            book.answer_knock(&expiring.invite_id, OPENER, NOW + WEEK),
            KnockOutcome::NotOutstanding
        );
        // Gone for good: an earlier clock reading doesn't bring it back.
        assert_eq!(
            book.answer_knock(&expiring.invite_id, OPENER, NOW),
            KnockOutcome::NotOutstanding
        );
        assert_eq!(book.records(NOW), []);
    }

    #[test]
    fn an_opened_invite_still_expires() {
        let mut book = InviteBook::new();
        let invite = issue(&mut book);
        book.answer_knock(&invite.invite_id, OPENER, NOW);
        assert_eq!(
            book.answer_knock(&invite.invite_id, OPENER, NOW + WEEK),
            KnockOutcome::NotOutstanding
        );
        assert_eq!(book.record(&invite.invite_id, NOW + WEEK), None);
    }

    #[test]
    fn the_book_is_capped_and_expired_invites_make_room() {
        let mut book = InviteBook::new();
        for _ in 0..MAX_OUTSTANDING_INVITES {
            issue(&mut book);
        }
        assert_eq!(
            book.issue(IDENTITY, address(), "", WEEK, NOW),
            Err(InviteError::TooManyOutstanding.into())
        );
        book.issue(IDENTITY, address(), "", WEEK, NOW + WEEK)
            .unwrap();
        assert_eq!(book.records(NOW + WEEK).len(), 1);
    }

    #[test]
    fn a_restored_invite_answers_as_it_did_before() {
        let mut book = InviteBook::new();
        let invite = issue(&mut book);
        book.answer_knock(&invite.invite_id, OPENER, NOW);
        let stored = book.records(NOW);

        let mut relaunched = InviteBook::new();
        for record in &stored {
            relaunched.restore(*record, NOW).unwrap();
        }
        assert_eq!(
            relaunched.answer_knock(&invite.invite_id, OPENER, NOW),
            KnockOutcome::Opened { first_time: false }
        );
        assert_eq!(
            relaunched.answer_knock(&invite.invite_id, OTHER, NOW),
            KnockOutcome::NotOutstanding
        );
        assert_eq!(
            relaunched.restore(stored[0], NOW),
            Err(InviteError::Duplicate)
        );
        assert_eq!(
            InviteBook::new().restore(stored[0], NOW + WEEK),
            Err(InviteError::Expired)
        );
    }

    #[test]
    fn a_restored_invite_cannot_outlast_the_longest_lifetime() {
        let record = |expires_at| InviteRecord {
            invite_id: [0x77; INVITE_ID_BYTES],
            expires_at,
            opened_by: None,
        };
        for too_far in [NOW + MAX_INVITE_LIFETIME_SECS + 1, u64::MAX] {
            let mut book = InviteBook::new();
            assert_eq!(
                book.restore(record(too_far), NOW),
                Err(InviteError::Lifetime)
            );
            assert_eq!(book.records(NOW), []);
        }
        let mut book = InviteBook::new();
        book.restore(record(NOW + MAX_INVITE_LIFETIME_SECS), NOW)
            .unwrap();
        assert_eq!(book.records(NOW).len(), 1);
    }

    #[test]
    fn restoring_respects_the_cap() {
        let mut book = InviteBook::new();
        for _ in 0..MAX_OUTSTANDING_INVITES {
            issue(&mut book);
        }
        let extra = InviteRecord {
            invite_id: [0x77; INVITE_ID_BYTES],
            expires_at: NOW + WEEK,
            opened_by: None,
        };
        assert_eq!(
            book.restore(extra, NOW),
            Err(InviteError::TooManyOutstanding)
        );
    }

    #[test]
    fn a_failed_random_source_issues_nothing() {
        scripted::with_seed(b"invite", || {
            let mut book = InviteBook::new();
            scripted::set_failing(true);
            assert_eq!(
                book.issue(IDENTITY, address(), "", WEEK, NOW),
                Err(PairingError::Random.into())
            );
            scripted::set_failing(false);
            assert_eq!(book.records(NOW), []);
        });
    }
}
