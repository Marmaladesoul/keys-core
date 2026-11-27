//! `CPace`, cipher suite `CPACE-RISTR255-SHA512`, initiator-responder setting.
//!
//! Implemented against [`CPACE_DRAFT`] (`draft-irtf-cfrg-cpace-21`). Section
//! numbers in the comments below refer to that revision. Only the pieces this
//! crate uses are implemented: the ristretto255 group environment (§8.3), the
//! generator derivation (§8.1, Appendix A.2), the initiator-responder
//! transcript (§6.3) and the ISK derivation (§7.2). The test vectors at the
//! bottom are the draft's Appendix A.1 and B.3, verbatim.
//!
//! This module knows nothing about codes, roles or messages. It turns
//! (PRS, CI, sid) into a public share and, given the peer's share and both
//! associated-data strings, into the ISK. The pairing layer above it decides
//! what those inputs are.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::secret::Secret;

/// The exact `CPace` specification revision this module implements.
pub const CPACE_DRAFT: &str = "draft-irtf-cfrg-cpace-21";

/// `G_Ristretto255.DSI` (§8.3).
const DSI: &[u8] = b"CPaceRistretto255";
/// `G.DSI || b"_ISK"`, the ISK domain separator (§7.2).
const DSI_ISK: &[u8] = b"CPaceRistretto255_ISK";
/// `H.s_in_bytes` for SHA-512: its input block size (§6.2).
const SHA512_BLOCK_BYTES: usize = 128;
/// `G_Ristretto255.field_size_bytes` (§8.3).
const FIELD_SIZE_BYTES: usize = 32;
/// Mask for the last little-endian byte of a sampled scalar that clears every
/// bit above `G_Ristretto255.group_size_bits` (252 = 31 * 8 + 4) (§8.3).
const SCALAR_TOP_BYTE_MASK: u8 = 0x0f;

/// Length of an encoded group element, the public share Ya or Yb.
pub const SHARE_BYTES: usize = FIELD_SIZE_BYTES;
/// Length of the ISK: the full SHA-512 output, `H.b_in_bytes`.
pub const ISK_BYTES: usize = 64;

/// Why a `CPace` run must abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CpaceError {
    /// The peer's share didn't decode to a ristretto255 element, or the
    /// shared point was the neutral element `G.I` (§7.2, §8.3).
    #[error("the peer's CPace share is not a valid group element")]
    InvalidShare,
    /// The operating system's random source failed.
    #[error("the system random source failed")]
    Random,
}

/// LEB128 (§6.3): each byte carries seven bits of the length, low bits
/// first, and its top bit says whether another byte follows. Shared with the
/// reader in `wire`.
pub(crate) const LEB128_PAYLOAD_BITS: u32 = 7;
pub(crate) const LEB128_PAYLOAD_MASK: u8 = 0x7f;
pub(crate) const LEB128_CONTINUATION: u8 = 0x80;

/// Appends the LEB128 encoding of `len` (§6.3, Appendix A.1.1).
fn push_leb128(out: &mut Vec<u8>, mut len: usize) {
    loop {
        let low =
            u8::try_from(len & usize::from(LEB128_PAYLOAD_MASK)).expect("masked to seven bits");
        len >>= LEB128_PAYLOAD_BITS;
        if len == 0 {
            out.push(low);
            return;
        }
        out.push(low | LEB128_CONTINUATION);
    }
}

/// `prepend_len(data)` appended to `out` (Appendix A.1.1).
pub(crate) fn push_prepend_len(out: &mut Vec<u8>, data: &[u8]) {
    push_leb128(out, data.len());
    out.extend_from_slice(data);
}

/// `lv_cat(parts...)` (Appendix A.1.3).
///
/// The buffer is sized exactly up front, so it never reallocates: callers
/// pass secrets (the code, K) as parts and wipe the result, and a growing
/// buffer would leave unwiped copies of them in freed memory.
pub(crate) fn lv_cat(parts: &[&[u8]]) -> Vec<u8> {
    let total = parts.iter().map(|part| prepend_len_size(part.len())).sum();
    let mut out = Vec::with_capacity(total);
    let capacity = out.capacity();
    for part in parts {
        push_prepend_len(&mut out, part);
    }
    debug_assert_eq!(out.len(), total, "lv_cat's size calculation is wrong");
    debug_assert_eq!(out.capacity(), capacity, "lv_cat reallocated");
    out
}

/// Length of `prepend_len(data)` for data of length `len`.
fn prepend_len_size(len: usize) -> usize {
    let mut leb_bytes = 1;
    let mut rest = len >> LEB128_PAYLOAD_BITS;
    while rest != 0 {
        leb_bytes += 1;
        rest >>= LEB128_PAYLOAD_BITS;
    }
    leb_bytes + len
}

/// `generator_string(G.DSI, PRS, CI, sid, H.s_in_bytes)` (§8.1, Appendix A.2).
/// It holds the password, so it is wiped when dropped.
fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Zeroizing<Vec<u8>> {
    let len_zpad = SHA512_BLOCK_BYTES
        .saturating_sub(1)
        .saturating_sub(prepend_len_size(prs.len()))
        .saturating_sub(prepend_len_size(DSI.len()));
    let zpad = vec![0u8; len_zpad];
    Zeroizing::new(lv_cat(&[DSI, prs, &zpad, ci, sid]))
}

/// `G.calculate_generator(H, PRS, CI, sid)` for ristretto255 (§8.3): hash the
/// generator string to `2 * field_size_bytes` and apply the RFC 9496 element
/// derivation. The generator is password-derived, so it is wiped on drop.
fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> Zeroizing<RistrettoPoint> {
    let gen_str = generator_string(prs, ci, sid);
    let mut hash = Zeroizing::new([0u8; 2 * FIELD_SIZE_BYTES]);
    Sha512::new_with_prefix(gen_str.as_slice()).finalize_into((&mut *hash).into());
    Zeroizing::new(RistrettoPoint::from_uniform_bytes(&hash))
}

/// A secret scalar, wiped on drop. Always held boxed (see [`Secret`] for
/// why): moving its owner must not copy it.
struct SecretScalar(Scalar);

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SecretScalar {
    /// `G.sample_scalar()` as RECOMMENDED for ristretto255 (§8.3): 32 random
    /// bytes with the bits above `group_size_bits` cleared, read little-endian.
    /// The result is below 2^252, so below the group order, and needs no
    /// reduction.
    // Boxed on purpose, here and below: the scalar must never be moved by
    // value once it exists.
    fn sample() -> Result<Box<Self>, CpaceError> {
        let mut bytes = Zeroizing::new([0u8; FIELD_SIZE_BYTES]);
        crate::random::fill(bytes.as_mut()).map_err(|_| CpaceError::Random)?;
        Ok(Self::from_sampled_bytes(&mut bytes))
    }

    /// Masks `bytes` in place and reads them as the scalar, which is written
    /// straight into its own allocation.
    #[allow(clippy::unnecessary_box_returns)]
    fn from_sampled_bytes(bytes: &mut [u8; FIELD_SIZE_BYTES]) -> Box<Self> {
        bytes[FIELD_SIZE_BYTES - 1] &= SCALAR_TOP_BYTE_MASK;
        let mut scalar = Box::new(Self(Scalar::ZERO));
        scalar.0 = Scalar::from_bytes_mod_order(*bytes);
        scalar
    }
}

/// `G.scalar_mult_vfy(y, X)` (§8.3) followed by the abort on `G.I` (§7.2):
/// `None` if `X` doesn't decode or the product is the neutral element.
fn scalar_mult_vfy(y: &SecretScalar, x: &[u8]) -> Option<Zeroizing<[u8; SHARE_BYTES]>> {
    let point = CompressedRistretto::from_slice(x).ok()?.decompress()?;
    // By reference, so the multiply isn't handed its own copy of the scalar.
    #[allow(clippy::op_ref)]
    let product = Zeroizing::new(&y.0 * &point);
    if product.is_identity() {
        return None;
    }
    Some(Zeroizing::new(product.compress().to_bytes()))
}

/// Which side of the initiator-responder transcript a party is on. The
/// initiator's `(Y, AD)` comes first in `transcript_ir` (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpaceRole {
    Initiator,
    Responder,
}

/// The intermediate session key, wiped on drop.
pub struct Isk(Secret<ISK_BYTES>);

impl Isk {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ISK_BYTES] {
        self.0.as_bytes()
    }
}

/// One party's half of a `CPace` run, between sending its share and receiving
/// the peer's. Consumed by [`CpaceParty::finish`], so a scalar is never
/// reused (§10.9).
pub struct CpaceParty {
    y: Box<SecretScalar>,
    share: [u8; SHARE_BYTES],
    sid: Vec<u8>,
}

impl CpaceParty {
    /// Computes the generator from `(PRS, CI, sid)`, samples a fresh scalar
    /// and computes this party's public share (§7.2).
    ///
    /// # Errors
    /// [`CpaceError::Random`] if the system random source fails.
    pub fn start(prs: &[u8], ci: &[u8], sid: &[u8]) -> Result<Self, CpaceError> {
        Ok(Self::with_scalar(prs, ci, sid, SecretScalar::sample()?))
    }

    fn with_scalar(prs: &[u8], ci: &[u8], sid: &[u8], y: Box<SecretScalar>) -> Self {
        let generator = calculate_generator(prs, ci, sid);
        // The share is public; the point on the way to it is not secret.
        #[allow(clippy::op_ref)] // by reference: no extra copy of the scalar
        let share = (&y.0 * &*generator).compress().to_bytes();
        Self {
            y,
            share,
            sid: sid.to_vec(),
        }
    }

    /// Registers the secret scalar with the freed-memory watch, by
    /// reference, so the test makes no copy of its own.
    #[cfg(test)]
    pub(crate) fn watch_secrets(&self) {
        crate::heap_watch::register(self.y.0.as_bytes());
    }

    /// This party's public share, `Ya` or `Yb`.
    #[must_use]
    pub fn share(&self) -> &[u8; SHARE_BYTES] {
        &self.share
    }

    /// Derives the ISK from the peer's share (§7.2):
    /// `ISK = H(lv_cat(DSI_ISK, sid, K) || transcript_ir(Ya, ADa, Yb, ADb))`.
    ///
    /// # Errors
    /// [`CpaceError::InvalidShare`] if the peer's share fails
    /// `scalar_mult_vfy`; the run must then abort.
    pub fn finish(
        self,
        role: CpaceRole,
        own_ad: &[u8],
        peer_share: &[u8],
        peer_ad: &[u8],
    ) -> Result<Isk, CpaceError> {
        let k = scalar_mult_vfy(&self.y, peer_share).ok_or(CpaceError::InvalidShare)?;
        let (ya, ada, yb, adb) = match role {
            CpaceRole::Initiator => (&self.share[..], own_ad, peer_share, peer_ad),
            CpaceRole::Responder => (peer_share, peer_ad, &self.share[..], own_ad),
        };
        let mut hasher = Sha512::new();
        hasher.update(Zeroizing::new(lv_cat(&[DSI_ISK, &self.sid, k.as_slice()])).as_slice());
        hasher.update(transcript_ir(ya, ada, yb, adb));
        let mut isk = Secret::zeroed();
        hasher.finalize_into(isk.as_mut().into());
        Ok(Isk(isk))
    }
}

/// `transcript_ir(Ya, ADa, Yb, ADb) = lv_cat(Ya, ADa) || lv_cat(Yb, ADb)` (§6.3).
fn transcript_ir(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
    let mut out = lv_cat(&[ya, ada]);
    out.extend_from_slice(&lv_cat(&[yb, adb]));
    out
}

#[cfg(test)]
mod tests {
    //! The draft's own test vectors: Appendix A.1 (string functions) and B.3
    //! (`CPACE-RISTR255-SHA512`), copied from `draft-irtf-cfrg-cpace-21`.
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[allow(clippy::unnecessary_box_returns)]
    fn scalar(s: &str) -> Box<SecretScalar> {
        let mut bytes: [u8; FIELD_SIZE_BYTES] = hex(s).try_into().expect("32 bytes");
        SecretScalar::from_sampled_bytes(&mut bytes)
    }

    // B.3.1 inputs.
    const PRS: &[u8] = b"Password";
    const CI: &str = "0b415f696e69746961746f720b425f726573706f6e646572";
    const SID: &str = "7e4b4791d6a8ef019b936c79fb7f2c57";
    // B.3.2 / B.3.3 inputs.
    const ADA: &[u8] = b"ADa";
    const ADB: &[u8] = b"ADb";
    const YA_SCALAR: &str = "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08";
    const YB_SCALAR: &str = "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d";

    #[test]
    fn a1_prepend_len_vectors() {
        let mut out = Vec::new();
        push_prepend_len(&mut out, b"");
        assert_eq!(out, hex("00"));

        let mut out = Vec::new();
        push_prepend_len(&mut out, b"1234");
        assert_eq!(out, hex("0431323334"));

        let range127: Vec<u8> = (0..127).collect();
        let mut out = Vec::new();
        push_prepend_len(&mut out, &range127);
        assert_eq!(out[0], 0x7f);
        assert_eq!(&out[1..], &range127[..]);

        let range128: Vec<u8> = (0..128).collect();
        let mut out = Vec::new();
        push_prepend_len(&mut out, &range128);
        assert_eq!(&out[..2], &hex("8001")[..]);
        assert_eq!(&out[2..], &range128[..]);
    }

    #[test]
    fn a1_lv_cat_vector() {
        assert_eq!(
            lv_cat(&[b"1234", b"5", b"", b"678"]),
            hex("043132333401350003363738")
        );
    }

    #[test]
    fn b31_generator_string_and_generator() {
        let gen_str = generator_string(PRS, &hex(CI), &hex(SID));
        assert_eq!(
            gen_str.as_slice(),
            hex("11435061636552697374726574746f3235350850617373776f726464
                 00000000000000000000000000000000000000000000000000000000
                 00000000000000000000000000000000000000000000000000000000
                 00000000000000000000000000000000000000000000000000000000
                 00000000000000000000000000000000180b415f696e69746961746f
                 720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f
                 2c57")
        );
        assert_eq!(
            Sha512::digest(gen_str.as_slice()).as_slice(),
            hex("da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288
                 b6663af06bf645c93cd1c51512307199c80e84908916d983b34af772
                 05f90851a657ee27")
        );
        let generator = calculate_generator(PRS, &hex(CI), &hex(SID));
        assert_eq!(
            generator.compress().to_bytes().to_vec(),
            hex("222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56")
        );
    }

    #[test]
    fn b32_to_b35_shares_k_and_isk() {
        let a = CpaceParty::with_scalar(PRS, &hex(CI), &hex(SID), scalar(YA_SCALAR));
        let b = CpaceParty::with_scalar(PRS, &hex(CI), &hex(SID), scalar(YB_SCALAR));
        let ya = hex("d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157");
        let yb = hex("3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258");
        assert_eq!(a.share().to_vec(), ya);
        assert_eq!(b.share().to_vec(), yb);

        // B.3.4: K agrees from both sides.
        let k = hex("80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f");
        assert_eq!(scalar_mult_vfy(&a.y, &yb).expect("valid").to_vec(), k);
        assert_eq!(scalar_mult_vfy(&b.y, &ya).expect("valid").to_vec(), k);

        // B.3.5: transcript_ir and the ISK.
        assert_eq!(
            transcript_ir(&ya, ADA, &yb, ADB),
            hex("20d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0e
                 ec482b915703414461203ea7e0b19560d7c0b0f5734f63b955286dfa
                 8232b5ebe63324e2d9e7433f725803414462")
        );
        let isk = hex("b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dc
             ae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c
             3fa2068af7900447");
        let isk_a = a
            .finish(CpaceRole::Initiator, ADA, &yb, ADB)
            .expect("valid");
        let isk_b = b
            .finish(CpaceRole::Responder, ADB, &ya, ADA)
            .expect("valid");
        assert_eq!(isk_a.as_bytes().to_vec(), isk);
        assert_eq!(isk_b.as_bytes().to_vec(), isk);
    }

    #[test]
    fn b310_scalar_mult_valid_input() {
        let s = scalar("7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05");
        let x = hex("2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");
        assert_eq!(
            scalar_mult_vfy(&s, &x).expect("valid").to_vec(),
            hex("7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e")
        );
    }

    #[test]
    fn b311_invalid_inputs_abort() {
        let s = scalar("7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05");
        let y_i1 = hex("2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");
        let y_i2 = [0u8; SHARE_BYTES];
        assert!(scalar_mult_vfy(&s, &y_i1).is_none());
        assert!(scalar_mult_vfy(&s, &y_i2).is_none());

        // And the protocol aborts on them (§8.3.1).
        let a = CpaceParty::with_scalar(PRS, &hex(CI), &hex(SID), scalar(YA_SCALAR));
        assert_eq!(
            a.finish(CpaceRole::Initiator, ADA, &y_i1, ADB).err(),
            Some(CpaceError::InvalidShare)
        );
        let a = CpaceParty::with_scalar(PRS, &hex(CI), &hex(SID), scalar(YA_SCALAR));
        assert_eq!(
            a.finish(CpaceRole::Initiator, ADA, &y_i2, ADB).err(),
            Some(CpaceError::InvalidShare)
        );
        // A share of the wrong length doesn't decode either.
        let a = CpaceParty::with_scalar(PRS, &hex(CI), &hex(SID), scalar(YA_SCALAR));
        assert_eq!(
            a.finish(CpaceRole::Initiator, ADA, &y_i1[..31], ADB).err(),
            Some(CpaceError::InvalidShare)
        );
    }

    #[test]
    fn different_passwords_give_different_isks() {
        let a = CpaceParty::start(b"123456", b"ci", b"sid").expect("rng");
        let b = CpaceParty::start(b"123457", b"ci", b"sid").expect("rng");
        let (ya, yb) = (*a.share(), *b.share());
        let isk_a = a
            .finish(CpaceRole::Initiator, b"", &yb, b"")
            .expect("valid");
        let isk_b = b
            .finish(CpaceRole::Responder, b"", &ya, b"")
            .expect("valid");
        assert_ne!(isk_a.as_bytes(), isk_b.as_bytes());
    }

    #[test]
    fn sampled_scalars_stay_below_two_to_the_252() {
        // Bits 252 to 255 are the top four bits of the last little-endian
        // byte. A literal here, not the production constant, so a wrong
        // constant can't vouch for itself.
        const BITS_252_AND_UP: u8 = 0xf0;
        for _ in 0..64 {
            let y = SecretScalar::sample().expect("rng");
            assert_eq!(y.0.to_bytes()[31] & BITS_252_AND_UP, 0);
        }
        // All-ones input: the mask is what brings it below 2^252.
        let mut ones = [0xff; FIELD_SIZE_BYTES];
        let y = SecretScalar::from_sampled_bytes(&mut ones);
        let mut expected = [0xff; FIELD_SIZE_BYTES];
        expected[31] = 0x0f;
        assert_eq!(y.0.to_bytes(), expected);
    }
}
