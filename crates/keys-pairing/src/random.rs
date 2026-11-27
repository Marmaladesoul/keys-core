//! The crate's one door to the system random source.
//!
//! Every nonce, scalar, key and code is drawn through [`fill`]. In this
//! crate's own test build, and in a fuzzing build (`--cfg fuzzing`, which
//! cargo-fuzz sets), a caller can script the bytes for its own thread: tests
//! pin the protocol's messages as known answers, and a fuzz target makes a
//! crash reproduce from its input. No other build contains the script, and
//! even where it exists a thread that never asked for it gets the system
//! source.

/// Fills `bytes` from the operating system's random source.
pub(crate) fn fill(bytes: &mut [u8]) -> Result<(), getrandom::Error> {
    #[cfg(any(test, fuzzing))]
    if let Some(scripted) = scripted::fill(bytes) {
        return scripted;
    }
    getrandom::getrandom(bytes)
}

#[cfg(any(test, fuzzing))]
pub(crate) mod scripted {
    //! A deterministic byte stream for known-answer tests: block `i` is
    //! `SHA-512(seed || i as u64 BE)`, and each [`fill`](super::fill) call
    //! starts on a fresh block.

    use std::cell::RefCell;

    use sha2::{Digest, Sha512};

    struct Script {
        seed: Vec<u8>,
        next_block: u64,
        /// While set, every draw fails, as a broken system source would.
        failing: bool,
    }

    thread_local! {
        static SCRIPT: RefCell<Option<Script>> = const { RefCell::new(None) };
    }

    /// Scripts this thread's random bytes from `seed`, from now on.
    pub(crate) fn start(seed: &[u8]) {
        SCRIPT.with_borrow_mut(|script| {
            *script = Some(Script {
                seed: seed.to_vec(),
                next_block: 0,
                failing: false,
            });
        });
    }

    /// Runs `body` with this thread's random bytes scripted from `seed`.
    #[cfg(test)]
    pub(crate) fn with_seed<T>(seed: &[u8], body: impl FnOnce() -> T) -> T {
        start(seed);
        let result = body();
        SCRIPT.with_borrow_mut(|script| *script = None);
        result
    }

    /// Makes this thread's scripted source fail every draw, or work again.
    ///
    /// # Panics
    /// If this thread has no script.
    #[cfg(test)]
    pub(crate) fn set_failing(failing: bool) {
        SCRIPT.with_borrow_mut(|script| {
            script.as_mut().expect("a scripted thread").failing = failing;
        });
    }

    /// Fills `bytes` from the script, if this thread has one: `None` if it
    /// has none, and the draw's result if it has.
    pub(super) fn fill(bytes: &mut [u8]) -> Option<Result<(), getrandom::Error>> {
        SCRIPT.with_borrow_mut(|script| {
            let script = script.as_mut()?;
            if script.failing {
                return Some(Err(getrandom::Error::UNSUPPORTED));
            }
            for chunk in bytes.chunks_mut(Sha512::output_size()) {
                let mut hasher = Sha512::new();
                hasher.update(&script.seed);
                hasher.update(script.next_block.to_be_bytes());
                script.next_block += 1;
                chunk.copy_from_slice(&hasher.finalize()[..chunk.len()]);
            }
            Some(Ok(()))
        })
    }
}
