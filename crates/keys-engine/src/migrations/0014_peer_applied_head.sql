-- Migration 0014: the peer copy last merged from each owner.
--
-- A per-device-key sync transport hands the engine each peer's latest KDBX
-- (`ingest_peer_from_kdbx`, under the peer's owner id). Merging one costs a
-- key derivation, and a client re-reads every peer's head on each launch,
-- so remembering what it already merged only in memory meant a full KDF
-- per peer per launch. This table records, per owner, the SHA-256 of the
-- exact bytes last merged without error; an ingest of those same bytes
-- under that owner is answered "no change" without deriving.
--
-- Mirror-local, never projected: it describes this mirror, so a mirror
-- rebuilt from its vault file starts without it and merges each peer's
-- copy again (a wholesale re-ingest clears it too). No watermark triggers.
CREATE TABLE peer_applied_head (
    owner          TEXT PRIMARY KEY NOT NULL,
    content_sha256 BLOB NOT NULL
);
