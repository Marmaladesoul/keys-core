//! `enable_diagnostic_log` end to end. Its own test binary because the
//! subscriber it installs is process-wide and can only be set once.

use keys_iroh_sync::enable_diagnostic_log;

#[test]
fn writes_filtered_events_and_enables_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sync.log");
    let path_str = path.to_str().unwrap().to_owned();

    enable_diagnostic_log(path_str.clone()).expect("first enable succeeds");
    tracing::debug!(target: "iroh_docs::engine::live", "debug-probe");
    tracing::trace!(target: "iroh_docs::actor", "trace-probe");
    tracing::info!(target: "unrelated_crate", "info-probe");

    let log = std::fs::read_to_string(&path).unwrap();
    assert!(log.contains("diagnostic log enabled"));
    assert!(log.contains("debug-probe"));
    assert!(!log.contains("trace-probe"), "trace must never be written");
    assert!(
        !log.contains("info-probe"),
        "other crates are capped at warn"
    );

    assert!(
        enable_diagnostic_log(path_str).is_err(),
        "a second enable in the same process fails"
    );
}
