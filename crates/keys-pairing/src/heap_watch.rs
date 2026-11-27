//! Test-only: a global allocator that looks inside every block the watching
//! thread frees, for byte strings the test registered as secret.
//!
//! "Wiped on drop" is invisible to ordinary tests: a secret that was copied
//! when its owner moved is wiped at its last home and left behind at every
//! earlier one. This makes it visible. A test registers a run's secrets as
//! they come into being, and at the end asserts that no block was freed
//! with any of them still in it.
//!
//! Only the thread that is watching is scanned, so tests running beside it
//! neither slow down nor trip it. Nothing here allocates or frees while a
//! block is being examined.

// The one place this crate needs `unsafe`: implementing `GlobalAlloc`.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;

/// The longest secret a test can register.
const MAX_NEEDLE_BYTES: usize = 32;
/// How many secrets one watch can hold.
const MAX_NEEDLES: usize = 12;

struct Needle {
    bytes: [u8; MAX_NEEDLE_BYTES],
    len: usize,
}

struct Watch {
    watching: bool,
    needles: [Needle; MAX_NEEDLES],
    count: usize,
    /// Blocks freed with a registered secret in them.
    hits: usize,
}

const NO_NEEDLE: Needle = Needle {
    bytes: [0; MAX_NEEDLE_BYTES],
    len: 0,
};

thread_local! {
    // `const`, with no destructor, so touching it from inside the allocator
    // neither allocates nor frees. Always borrowed in place: the secrets are
    // copied once, into this slot, and never onto anyone's stack (a stale
    // stack copy can end up in a later heap block's padding and trip the
    // watch on the harness's own leavings).
    static WATCH: RefCell<Watch> = const {
        RefCell::new(Watch {
            watching: false,
            needles: [NO_NEEDLE; MAX_NEEDLES],
            count: 0,
            hits: 0,
        })
    };
}

pub(crate) struct WatchingAllocator;

unsafe impl GlobalAlloc for WatchingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // `try_with`: a thread that is shutting down has no watch to consult.
        // `try_borrow_mut`: nothing in this module frees while it holds the
        // borrow, but if something ever did, skip rather than panic here.
        let _ = WATCH.try_with(|watch| {
            if let Ok(mut watch) = watch.try_borrow_mut()
                && watch.watching
            {
                // SAFETY: `block` is a live allocation of `layout.size()`
                // bytes until the `System.dealloc` below. Some of them may
                // never have been written; they are read as `u8` only to
                // compare them, which the hardware permits and Rust's
                // model strictly does not (Miri would object). Test-only,
                // and the price of looking at freed memory at all.
                let freed = unsafe { std::slice::from_raw_parts(block, layout.size()) };
                let found = watch.needles[..watch.count].iter().any(|needle| {
                    freed
                        .windows(needle.len)
                        .any(|window| window == &needle.bytes[..needle.len])
                });
                if found {
                    watch.hits += 1;
                }
            }
        });
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.dealloc(block, layout) }
    }
}

/// Starts watching this thread's frees. Any earlier watch is discarded.
pub(crate) fn start() {
    WATCH.with_borrow_mut(|watch| {
        watch.watching = true;
        watch.count = 0;
        watch.hits = 0;
    });
}

/// Registers `secret` (or its first [`MAX_NEEDLE_BYTES`] bytes) with this
/// thread's watch. Pass a reference to the secret where it lives: a copy
/// made to pass it here is one more thing to leave behind.
pub(crate) fn register(secret: &[u8]) {
    WATCH.with_borrow_mut(|watch| {
        assert!(watch.watching, "start() the watch first");
        assert!(watch.count < MAX_NEEDLES, "too many secrets for one watch");
        assert!(!secret.is_empty(), "an empty secret matches everything");
        let len = secret.len().min(MAX_NEEDLE_BYTES);
        let slot = watch.count;
        watch.needles[slot].bytes[..len].copy_from_slice(&secret[..len]);
        watch.needles[slot].len = len;
        watch.count += 1;
    });
}

/// Stops watching and returns how many blocks were freed with a registered
/// secret still in them.
pub(crate) fn finish() -> usize {
    WATCH.with_borrow_mut(|watch| {
        assert!(watch.watching, "start() the watch first");
        watch.watching = false;
        for needle in &mut watch.needles {
            needle.bytes.fill(0);
            needle.len = 0;
        }
        watch.count = 0;
        watch.hits
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_watch_sees_a_secret_left_in_a_freed_block_and_not_a_wiped_one() {
        use std::hint::black_box;

        start();
        // `black_box` keeps the optimiser from deleting the allocations in
        // a release build, where this check matters as much as in debug.
        // Left behind: freed as it is.
        let left_behind = black_box(Box::new([0x5a_u8; MAX_NEEDLE_BYTES]));
        register(&*left_behind);
        drop(left_behind);
        // Wiped first: nothing to find.
        let mut wiped = black_box(Box::new([0x5a_u8; MAX_NEEDLE_BYTES]));
        wiped.fill(0);
        drop(black_box(wiped));
        assert_eq!(finish(), 1);
    }
}
