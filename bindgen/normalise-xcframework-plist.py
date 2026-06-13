#!/usr/bin/env python3
"""Canonicalise an xcframework Info.plist so the build is byte-deterministic.

`xcodebuild -create-xcframework` emits the `AvailableLibraries` array in a
non-stable order once there's more than one slice — re-running produces the
same slices but shuffled, which breaks the idempotency gate the bindgen
build scripts rely on. Sort the libraries (and each slice's architecture
list) into a fixed order and re-serialise with sorted keys, so identical
inputs always yield byte-identical output.

Used by both `build-swift.sh` and `build-swift-iroh-sync.sh`.
"""

import plistlib
import sys


def main(path: str) -> None:
    with open(path, "rb") as f:
        data = plistlib.load(f)

    for library in data.get("AvailableLibraries", []):
        archs = library.get("SupportedArchitectures")
        if archs is not None:
            archs.sort()

    data.get("AvailableLibraries", []).sort(
        key=lambda library: library.get("LibraryIdentifier", "")
    )

    with open(path, "wb") as f:
        plistlib.dump(data, f, sort_keys=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <xcframework>/Info.plist")
    main(sys.argv[1])
