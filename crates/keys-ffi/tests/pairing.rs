//! The pairing surface's refusals of a misused call, through the seam and on
//! the system clock a client gets. What the sheets do with well-formed
//! calls is proven by keyhole's `pairing-*.sh` scenarios.

use keys_ffi::{
    PairingCredentials, PairingDisplaySheet, PairingFfiError, PairingOutcomeFfi, PairingTypeSheet,
    PairingTypeStatus,
};

const DISPLAY_ENDPOINT: [u8; 32] = [0xd1; 32];
const TYPING_ENDPOINT: [u8; 32] = [0x71; 32];
const OTHER_ENDPOINT: [u8; 32] = [0x57; 32];
/// One byte short of an endpoint id.
const SHORT_ENDPOINT: [u8; 31] = [0x71; 31];

fn typing_sheet() -> std::sync::Arc<PairingTypeSheet> {
    PairingTypeSheet::open(
        PairingCredentials::Device,
        TYPING_ENDPOINT.to_vec(),
        DISPLAY_ENDPOINT.to_vec(),
    )
    .expect("open a typing sheet")
}

#[test]
fn an_endpoint_id_of_the_wrong_length_is_refused() {
    assert!(matches!(
        PairingDisplaySheet::open(PairingCredentials::Device, SHORT_ENDPOINT.to_vec()),
        Err(PairingFfiError::InvalidKeyLength)
    ));
    assert!(matches!(
        PairingTypeSheet::open(
            PairingCredentials::Device,
            TYPING_ENDPOINT.to_vec(),
            SHORT_ENDPOINT.to_vec(),
        ),
        Err(PairingFfiError::InvalidKeyLength)
    ));
    let display = PairingDisplaySheet::open(PairingCredentials::Device, DISPLAY_ENDPOINT.to_vec())
        .expect("open a displaying sheet");
    assert!(matches!(
        display.handle(SHORT_ENDPOINT.to_vec(), vec![1]),
        Err(PairingFfiError::InvalidKeyLength)
    ));
    assert!(matches!(
        display.abandon_run_of(SHORT_ENDPOINT.to_vec()),
        Err(PairingFfiError::InvalidKeyLength)
    ));
}

#[test]
fn a_failed_connection_abandons_only_a_run_with_its_own_endpoint() {
    let typing = typing_sheet();
    let display = PairingDisplaySheet::open(PairingCredentials::Device, DISPLAY_ENDPOINT.to_vec())
        .expect("open a displaying sheet");
    // No run in flight: nothing happens, and it isn't an error.
    assert!(matches!(
        display.abandon_run_of(TYPING_ENDPOINT.to_vec()),
        Ok(PairingOutcomeFfi::Ignored)
    ));
    let hello = typing.submit_code("123456".to_owned()).expect("a Hello");
    display
        .handle(TYPING_ENDPOINT.to_vec(), hello)
        .expect("handle the Hello");
    // Some other endpoint's connection failing leaves the run alone.
    assert!(matches!(
        display.abandon_run_of(OTHER_ENDPOINT.to_vec()),
        Ok(PairingOutcomeFfi::Ignored)
    ));
    assert_eq!(display.shown_code().expect("status"), None);
    // The run's own endpoint's does not.
    assert!(matches!(
        display.abandon_run_of(TYPING_ENDPOINT.to_vec()),
        Ok(PairingOutcomeFfi::RunFailed { runs_left: 2, .. })
    ));
    assert!(display.shown_code().expect("status").is_some());
}

#[test]
fn a_code_that_is_not_six_digits_is_refused_and_spends_nothing() {
    let typing = typing_sheet();
    let budget = typing.status();
    for typed in ["", "12345", "1234567", "12345a", "123 456"] {
        assert!(
            matches!(
                typing.submit_code(typed.to_owned()),
                Err(PairingFfiError::MalformedCode)
            ),
            "typed {typed:?}"
        );
    }
    assert_eq!(typing.status(), budget);
    assert!(matches!(budget, PairingTypeStatus::AwaitingCode { .. }));
}

#[test]
fn calls_that_do_not_fit_the_sheets_state_are_refused() {
    let typing = typing_sheet();
    // No run in flight to give up on.
    assert!(matches!(
        typing.abandon_run(),
        Err(PairingFfiError::WrongState)
    ));
    let hello = typing.submit_code("123456".to_owned()).expect("a Hello");
    // One run at a time.
    assert!(matches!(
        typing.submit_code("123456".to_owned()),
        Err(PairingFfiError::WrongState)
    ));

    let display = PairingDisplaySheet::open(PairingCredentials::Device, DISPLAY_ENDPOINT.to_vec())
        .expect("open a displaying sheet");
    assert!(matches!(
        display.abandon_run(),
        Err(PairingFfiError::WrongState)
    ));
    let share = display
        .handle(TYPING_ENDPOINT.to_vec(), hello)
        .expect("handle the Hello");
    assert!(matches!(share.outcome, PairingOutcomeFfi::Continue));
    // "New Code" applies only while a code is showing.
    assert!(matches!(
        display.new_code(),
        Err(PairingFfiError::WrongState)
    ));
    assert_eq!(display.shown_code().expect("status"), None);
}
