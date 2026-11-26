import XCTest
@testable import KeysCoreFFI

final class SmokeTests: XCTestCase {
    /// Slice 1 invariant: a Swift caller can round-trip a string through
    /// the uniffi-generated FFI. Replaced by real `Vault` round-trips in
    /// later slices, but `ping()` stays as the trivial sanity check.
    func testPingRoundTrip() throws {
        XCTAssertEqual(ping(), "keys-ffi alive")
    }

    /// The transport's exports ship in the same component as the engine's:
    /// one import reaches both.
    func testTransportSharesTheComponent() throws {
        XCTAssertEqual(identityGenerate().secretKeyBytes.count, 32)
    }
}
