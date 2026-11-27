//! The first words on a pairing connection.
//!
//! Whoever opens a connection says, in one message, what it is for, and gets
//! a one-byte answer before anything else happens:
//!
//! - **Knock**: "I am opening the invite with this id." Answered from the
//!   [`InviteBook`](crate::invite::InviteBook), with or without a sheet
//!   open. Nothing follows it.
//! - **Call**: "I am about to type a code for a pairing of this kind; are
//!   you showing one?" The side that types dials.
//! - **Approach**: "I am showing a code for a pairing of this kind; type it
//!   here." The side that shows dials, which is how a device already in an
//!   account reaches a new device it discovered.
//!
//! A Call or an Approach is accepted only while a sheet of the matching
//! kind and the opposite role is open and free. So a typing side learns the
//! other sheet is there before the person types anything, and a refusal
//! costs neither sheet a run. Once one is accepted, the exchange's own
//! messages follow on the same connection.
//!
//! None of this is authenticated beyond the transport's endpoint ids, and
//! none of it needs to be: a greeting moves no secret and proves nothing.
//! Which endpoint a side ends up running the exchange with is untrusted
//! input to the exchange, whose code is what the person verifies.
//!
//! Wire types 7 to 11 belong to this module; 1 to 6 are the exchange's and
//! the session's (see `protocol`), so a greeting that strays into a run
//! reads there as garbage and fails it like any other.

use crate::invite::{INVITE_ID_BYTES, InviteId, KnockOutcome};
use crate::protocol::PairingKind;

/// The longest greeting or answer, for a transport to bound its first read.
pub const MAX_GREETING_BYTES: usize = 1 + INVITE_ID_BYTES;

const TYPE_KNOCK: u8 = 7;
const TYPE_KNOCK_ANSWER: u8 = 8;
const TYPE_APPROACH: u8 = 9;
const TYPE_CALL: u8 = 10;
const TYPE_MEETING_ANSWER: u8 = 11;

// The byte after an answer's type. Each is written by `encode` and matched
// by `decode`, so the two can't drift apart.
const KNOCK_OPENED: u8 = 1;
const KNOCK_NOT_OUTSTANDING: u8 = 2;
const MEETING_ACCEPTED: u8 = 1;
const MEETING_NOT_LISTENING: u8 = 2;
const MEETING_BUSY: u8 = 3;

/// What the opener of a connection wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Greeting {
    /// The sender is opening the invite with this id.
    Knock { invite_id: InviteId },
    /// The sender shows a code; the receiver is asked to type it.
    Approach { kind: PairingKind },
    /// The sender will type a code; the receiver is asked whether it shows
    /// one.
    Call { kind: PairingKind },
}

impl Greeting {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Knock { invite_id } => {
                let mut message = Vec::with_capacity(MAX_GREETING_BYTES);
                message.push(TYPE_KNOCK);
                message.extend_from_slice(invite_id);
                message
            }
            Self::Approach { kind } => vec![TYPE_APPROACH, kind.wire()],
            Self::Call { kind } => vec![TYPE_CALL, kind.wire()],
        }
    }

    /// Reads a greeting. `None` for anything that isn't exactly one.
    #[must_use]
    pub fn decode(message: &[u8]) -> Option<Self> {
        let (&tag, rest) = message.split_first()?;
        match tag {
            TYPE_KNOCK => Some(Self::Knock {
                invite_id: rest.try_into().ok()?,
            }),
            TYPE_APPROACH | TYPE_CALL => {
                let [kind] = rest else { return None };
                let kind = PairingKind::from_wire(*kind)?;
                Some(if tag == TYPE_APPROACH {
                    Self::Approach { kind }
                } else {
                    Self::Call { kind }
                })
            }
            _ => None,
        }
    }
}

/// The answer to a knock, on the wire. [`KnockOutcome`] without the detail
/// only the issuer needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnockAnswer {
    /// The invite is outstanding and the knocker is its opener.
    Opened,
    /// Nothing to open. Don't knock again.
    NotOutstanding,
}

impl From<KnockOutcome> for KnockAnswer {
    fn from(outcome: KnockOutcome) -> Self {
        match outcome {
            KnockOutcome::Opened { .. } => Self::Opened,
            KnockOutcome::NotOutstanding => Self::NotOutstanding,
        }
    }
}

impl KnockAnswer {
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let answer = match self {
            Self::Opened => KNOCK_OPENED,
            Self::NotOutstanding => KNOCK_NOT_OUTSTANDING,
        };
        vec![TYPE_KNOCK_ANSWER, answer]
    }

    #[must_use]
    pub fn decode(message: &[u8]) -> Option<Self> {
        match message {
            [TYPE_KNOCK_ANSWER, KNOCK_OPENED] => Some(Self::Opened),
            [TYPE_KNOCK_ANSWER, KNOCK_NOT_OUTSTANDING] => Some(Self::NotOutstanding),
            _ => None,
        }
    }
}

/// The answer to a Call or an Approach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetingAnswer {
    /// A matching sheet is open and free: go on.
    Accepted,
    /// No sheet here is open for that. One answer whether none is open at
    /// all or the open one is of another kind or role.
    NotListening,
    /// A matching sheet is open but taken by someone else.
    Busy,
}

impl MeetingAnswer {
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let answer = match self {
            Self::Accepted => MEETING_ACCEPTED,
            Self::NotListening => MEETING_NOT_LISTENING,
            Self::Busy => MEETING_BUSY,
        };
        vec![TYPE_MEETING_ANSWER, answer]
    }

    #[must_use]
    pub fn decode(message: &[u8]) -> Option<Self> {
        match message {
            [TYPE_MEETING_ANSWER, MEETING_ACCEPTED] => Some(Self::Accepted),
            [TYPE_MEETING_ANSWER, MEETING_NOT_LISTENING] => Some(Self::NotListening),
            [TYPE_MEETING_ANSWER, MEETING_BUSY] => Some(Self::Busy),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MessageType;

    const INVITE_ID: InviteId = [0x1d; INVITE_ID_BYTES];

    fn every_greeting() -> Vec<Greeting> {
        vec![
            Greeting::Knock {
                invite_id: INVITE_ID,
            },
            Greeting::Approach {
                kind: PairingKind::Device,
            },
            Greeting::Approach {
                kind: PairingKind::Person,
            },
            Greeting::Call {
                kind: PairingKind::Device,
            },
            Greeting::Call {
                kind: PairingKind::Person,
            },
        ]
    }

    #[test]
    fn greetings_round_trip_and_fit_the_bound() {
        for greeting in every_greeting() {
            let encoded = greeting.encode();
            assert!(encoded.len() <= MAX_GREETING_BYTES);
            assert_eq!(Greeting::decode(&encoded), Some(greeting));
        }
    }

    /// The bytes themselves, so a change to them is a deliberate one.
    #[test]
    fn the_wire_forms_are_pinned() {
        let mut knock = vec![7];
        knock.extend_from_slice(&INVITE_ID);
        assert_eq!(
            Greeting::Knock {
                invite_id: INVITE_ID
            }
            .encode(),
            knock
        );
        assert_eq!(
            Greeting::Approach {
                kind: PairingKind::Device
            }
            .encode(),
            [9, 1]
        );
        assert_eq!(
            Greeting::Call {
                kind: PairingKind::Person
            }
            .encode(),
            [10, 2]
        );
        assert_eq!(KnockAnswer::Opened.encode(), [8, 1]);
        assert_eq!(KnockAnswer::NotOutstanding.encode(), [8, 2]);
        assert_eq!(MeetingAnswer::Accepted.encode(), [11, 1]);
        assert_eq!(MeetingAnswer::NotListening.encode(), [11, 2]);
        assert_eq!(MeetingAnswer::Busy.encode(), [11, 3]);
    }

    #[test]
    fn anything_but_exactly_a_greeting_is_refused() {
        for greeting in every_greeting() {
            let encoded = greeting.encode();
            let mut trailing = encoded.clone();
            trailing.push(0);
            assert_eq!(Greeting::decode(&trailing), None);
            assert_eq!(Greeting::decode(&encoded[..encoded.len() - 1]), None);
        }
        assert_eq!(Greeting::decode(&[]), None);
        // An unknown kind, and an answer or an exchange message where a
        // greeting belongs.
        assert_eq!(Greeting::decode(&[9, 0]), None);
        assert_eq!(Greeting::decode(&[10, 3]), None);
        assert_eq!(Greeting::decode(&[8, 1]), None);
        assert_eq!(Greeting::decode(&[1, 1, 1]), None);
    }

    #[test]
    fn answers_round_trip_and_refuse_everything_else() {
        for answer in [KnockAnswer::Opened, KnockAnswer::NotOutstanding] {
            assert_eq!(KnockAnswer::decode(&answer.encode()), Some(answer));
        }
        for answer in [
            MeetingAnswer::Accepted,
            MeetingAnswer::NotListening,
            MeetingAnswer::Busy,
        ] {
            assert_eq!(MeetingAnswer::decode(&answer.encode()), Some(answer));
        }
        for bad in [&[][..], &[8], &[8, 0], &[8, 3], &[8, 1, 0], &[11, 1]] {
            assert_eq!(KnockAnswer::decode(bad), None, "{bad:?}");
        }
        for bad in [&[][..], &[11], &[11, 0], &[11, 4], &[11, 1, 0], &[8, 1]] {
            assert_eq!(MeetingAnswer::decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_knock_outcome_answers_without_saying_whether_it_was_the_first() {
        assert_eq!(
            KnockAnswer::from(KnockOutcome::Opened { first_time: true }),
            KnockAnswer::from(KnockOutcome::Opened { first_time: false })
        );
        assert_eq!(
            KnockAnswer::from(KnockOutcome::NotOutstanding),
            KnockAnswer::NotOutstanding
        );
    }

    /// The exchange and the session never read a greeting as one of theirs.
    #[test]
    fn greeting_types_are_not_exchange_types() {
        for tag in [
            TYPE_KNOCK,
            TYPE_KNOCK_ANSWER,
            TYPE_APPROACH,
            TYPE_CALL,
            TYPE_MEETING_ANSWER,
        ] {
            assert_eq!(MessageType::of(&[tag]), None);
        }
    }
}
