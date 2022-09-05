//! A cryptographically secure fast erasure (i.e. forward secure) pseudo-random
//! number generator, based on the sponge/duplex construction and the keccak-*f*
//! permutation.
//!
//! Prioritizes security above performance (speed).
//!
//! # Usage
//! To create an instance of the RNG, preferably use
//! [`RngState::new_from_getrandom`]. You can hash in additional data using
//! [`RngState::seed`] if wanted. To generate random data use
//! [`RngState::fill_random_bytes`] to fill a buffer with random bytes, or
//! [`RngState::get_random_bytes`] to obtain an array filled with random bytes.
//! The RNG can always be reseeded (if you want backward security) using
//! [`RngState::seed_with_getrandom`].
//!
//! # Examples
//! Basic usage:
//! ```
//! use fast_erasure_shake_rng::RngState;
//!
//! let mut rng = RngState::new_from_getrandom().unwrap();
//! let key = rng.get_random_bytes::<32>();
//! ```
//!
//! Reseeding for backward security:
//! ```
//! use fast_erasure_shake_rng::RngState;
//!
//! let mut rng = RngState::new_from_getrandom().unwrap();
//! let key1 = rng.get_random_bytes::<32>();
//! // do other things ...
//! // later:
//! rng.seed_with_getrandom().unwrap();
//! let key2 = rng.get_random_bytes::<1000>();
//! ```
//!
//! Hashing in additional data, to reduce reliance on the OS RNG:
//! ```
//! use fast_erasure_shake_rng::RngState;
//!
//! let mut rng = RngState::new_from_getrandom().unwrap();
//! # #[cfg(not(miri))] {
//! let mut user_dice_rolls = String::new();
//! std::io::stdin().read_line(&mut user_dice_rolls).unwrap();
//! rng.seed(user_dice_rolls.as_ref());
//! # }
//!
//! let key = rng.get_random_bytes::<32>();
//! ```
//!
//! # Determinism & Portability
//! This PRNG is deterministic, meaning that it gives the same output when
//! seeded with the same input(s). Therefore it is necessary to seed it with a
//! non-deterministic source of randomness. The [`RngState::new_from_getrandom`]
//! method crates an instance of the PRNG seeded with randomness obtained from
//! the OS RNG (using the [`getrandom` crate]).
//!
//! The PRNG is not portable/reproducible though, meaning that the output given
//! the same seeding material may differ between platforms and versions. In
//! particular, the output depends on the targets endianness and the version
//! number of this crate. If you need a PRNG that is deterministic and portable,
//! and don't need the ability to reseed, use a standard XOF, like SHAKE256.
//!
//! # Crate Features
//! - `getrandom` (default): Enable dependency on the [`getrandom` crate]. This
//!   enables convenient and secure ways to seed the RNG, e.g.
//!   [`RngState::new_from_getrandom`].
//! - `rand-core`: Enable dependency on the [`rand_core` crate]. This enables
//!   implementations of the Rng traits from `rand_core` for [`RngState`].
//!
//! # RNGs and Cryptography Notes
//! ## Attacker controlled entropy sources
//! There is a widespread idea that adding as many entropy sources as possible
//! to an RNG is always a good idea. Unfortunately, life is not that easy. If an
//! entropy source is attacker controlled, it can actually be used to weaken or
//! break the RNG. This does require the malicious entropy source to know or
//! guess the input from other (earlier added) entropy sources, or know the RNG
//! state (i.e. the randomness pool). While this is not a mild assumption, it is
//! more conceivable for the malicious entropy source to have access to these
//! inputs than for the attacker himself to have them. Therefore it is still a
//! good idea to be a bit careful with adding entropy sources. See e.g.
//! <https://blog.cr.yp.to/20140205-entropy.html> for more information.
//!
//! ## Backward security
//! This RNG allows for reseeding, i.e. hash extra entropy into the state (after
//! initial use). This would provide backward security: even if an attacker has
//! observed the RNG state in the past, he won't be able to predict the output
//! of the RNG after the reseed operation has happend. In practice though, if an
//! attacker is able to see the RNG state you have much worse problems then RNG
//! security if you want to perform crypto. Hence there is little to no reason
//! to actually reseed the RNG after some time.
//!
//! # Design
//! I initially thought that just a sponge/duplex construction over some
//! (secure) permutation, would yield a secure RNG, but unfortunately that
//! construction is not forward secure. The problem is that the used
//! permutation, keccak-f\[1600\] is efficiently invertible. Hence if no reseed
//! is performed after obtaining random bytes, an attacker that obtained the
//! final state of the RNG could just apply the inverse permutation repeatedly
//! to find all the bytes that were emitted since the last reseed.
//!
//! What makes the sponge construction still secure for a hash function or XOF
//! is that the bytes in the capacity part of the state are never published,
//! unlike what we have to assume for forward security of the RNG. What would
//! solve the problem is to zeroize the capacity part of the state after every
//! permutation application. But then the RNG doesn't maintain a secret entropy
//! pool: given only one rate sized output, one could compute all future values
//! until a reseed. Hence we actually need two separate capacity parts in the
//! state: one which is always (that is, every time after outputting random
//! bytes) zeroized for forward secrecy and one that acts as the usual (entropy
//! collecting) state part.
//!
//! ## Detailed description
//! The keccak state consists, as usual, of 1600 bits, divided into 25 lanes of
//! 64 bits each. We divide it into three "areas":
//!
//! 1. An area we call the "rate area", consisting of the top 9 lanes, therefore
//! sized 576 bits.
//! 2. An area we call the "zeroized capacity area", consisting of the next 8
//! lanes, therefore sized 512 bits.
//! 3. An area we call the "capacity area", consisting of the last 8 lanes,
//! therefore sized 512 bits.
//!
//! We now define three basic actions on this state, which will serve as the
//! building blocks for all other (user facing) operations:
//!
//! 1. A basic action we call "input". First xor 576 bits of input data into the
//! "rate area" of the state. Then apply keccak-f to the state.
//! 2. A basic action we call "initial-output". First output the bytes in the
//! "rate area" as random output bytes. Then apply keccak-f.
//! 3. A basic action we call "intermediate-output". First output the bytes in
//! the "rate area" and the "zeroized capacity area" as random output bytes.
//! Then apply keccak-f to the state.
//! 4. A basic action we call "make-forward-secure". Zeroize (i.e., fill with
//! zero/null bytes) the "zeroized capacity area".
//!
//! The first basic actions is used to absorb entropy from inputs into the
//! state. The next two are used squeeze output from the state. The action
//! "make-forward-secure" creates a point of forward-security: if the state is
//! leaked after this action then an attacker won't be able to infer inputs to
//! or outputs from the RNG performed before this action.
//!
//! In a diagram:
//! ```ascii
//! Basic action 1: input                     State:      Basic action 2: initial-output
//!                                          ┌────────┐
//!                                          │Rate    │
//!                               Xor input  │        │  Output
//!                              ───────────►│9 lanes ├───────────►
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          ├────────┤
//!                                          │Zeroized│
//!                            Leave alone   │capacity│  Leave alone
//!                                          │        │
//!                                          │8 lanes │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          ├────────┤
//!                                          │Capacity│
//!                            Leave alone   │        │  Leave alone
//!                                          │8 lanes │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//! Then apply Keccak-f1600 to "state".      │        │   Then apply Keccak-f1600 to "state".
//!                                          │        │
//!                                          └────────┘
//!
//!
//! Basic action 3: intermediate-output       State:      Basic action 4: make-forward-secure
//!                                          ┌────────┐
//!                                          │Rate    │
//!                                  Output  │        │  Leave alone
//!                              ◄───────────┤9 lanes │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          ├────────┤
//!                                          │Zeroized│
//!                                  Output  │capacity│  Zeroize
//!                              ◄───────────┤        │◄───────────
//!                                          │8 lanes │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//!                                          ├────────┤
//!                                          │Capacity│
//!                            Leave alone   │        │  Leave alone
//!                                          │8 lanes │
//!                                          │        │
//!                                          │        │
//!                                          │        │
//! Then apply Keccak-f1600 to "state".      │        │
//!                                          │        │
//!                                          └────────┘
//! ```
//!
//! Inputting data into the the RNG works as follows: The data is padded to a
//! multiple of 576 bits (72 bytes) using simple 10*1 bit padding. For each 576
//! bit chunk of input, the basic action "input" is executed with this chunk as
//! input. Finally, the basic action "make-forward-secure" is performed.
//!
//! Outputting data from the RNG works as follows: First, the basic action
//! "initial-output" is executed, and the output of it is used as the first part
//! of the output of the RNG. If more data was requested (i.e., more than 72
//! bytes), then the basic action "intermediate-output" is executed repeatedly,
//! until enough output has been generated. Finally, the basic action
//! "make-forward-secure" is performed.
//!
//! [`getrandom` crate]: https://crates.io/crates/getrandom
//! [`rand_core` crate]: https://crates.io/crates/rand_core
#![cfg_attr(doc, feature(doc_cfg))]
#![no_std]
#![forbid(rust_2018_compatibility, unsafe_op_in_unsafe_fn)]
#![deny(future_incompatible, rust_2018_idioms)]
#![warn(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#![allow(clippy::needless_lifetimes)]

const LANES: usize = 25;
const BITS: usize = 1600; // LANES * 2^L
const CAPACITY_BITS: usize = 512;
const RATE_BITS: usize = BITS - 2 * CAPACITY_BITS;
const CAPACITY_BYTES: usize = CAPACITY_BITS / 8;
const RATE_BYTES: usize = RATE_BITS / 8;
const CAPACITY_LANES: usize = CAPACITY_BYTES / 8;
const RATE_LANES: usize = RATE_BYTES / 8;

#[allow(clippy::assertions_on_constants)]
const _: () = assert!(LANES == RATE_LANES + 2 * CAPACITY_LANES);

/// Convert a slice of `u64`s into a slice of bytes (`u8`s). Result depends on
/// endianness.
fn u64_slice_as_ne_bytes<'a>(slice: &'a [u64]) -> &'a [u8] {
    let len: usize = core::mem::size_of_val::<[u64]>(slice);
    unsafe { core::slice::from_raw_parts(slice.as_ptr().cast(), len) }
}

/// Convert a slice of `u64`s into a slice of bytes (`u8`s). Result depends on
/// endianness.
fn u64_slice_as_ne_bytes_mut<'a>(slice: &'a mut [u64]) -> &'a mut [u8] {
    let len: usize = core::mem::size_of_val::<[u64]>(slice);
    unsafe { core::slice::from_raw_parts_mut(slice.as_mut_ptr().cast(), len) }
}

/// Module constaining a structure for the keccak state and functions to operate
/// on it in terms of the three "areas" as defined in the top level
/// documentation.
mod internal_state;
use internal_state::InternalState;

/// The PRNG this crate is all about. Cryptographically secure fast-erasure
/// deterministic pseudo-random number generator (PRNG). It is deterministic but
/// not portable/reproducible.
///
/// # Usage
/// To create an instance of the RNG, preferably use
/// [`Self::new_from_getrandom`]. You can hash in additional data using
/// [`Self::seed`] if wanted. To generate random data use
/// [`Self::fill_random_bytes`] to fill a buffer with random bytes, or
/// [`Self::get_random_bytes`] to obtain an array filled with random bytes. The
/// RNG can always be reseeded (if you want backward security) using
/// [`Self::seed_with_getrandom`].
///
/// # Examples
/// Basic usage:
/// ```
/// use fast_erasure_shake_rng::RngState;
///
/// let mut rng = RngState::new_from_getrandom().unwrap();
/// let key = rng.get_random_bytes::<32>();
/// ```
///
/// Reseeding for backward security:
/// ```
/// use fast_erasure_shake_rng::RngState;
///
/// let mut rng = RngState::new_from_getrandom().unwrap();
/// let key1 = rng.get_random_bytes::<32>();
/// // do other things ...
/// // later:
/// rng.seed_with_getrandom().unwrap();
/// let key2 = rng.get_random_bytes::<1000>();
/// ```
///
/// # Determinism & Portability
/// This PRNG is deterministic, meaning that it gives the same output when
/// seeded with the same input(s). Therefore it is necessary to seed it with a
/// non-deterministic source of randomness. The [`Self::new_from_getrandom`]
/// method crates an instance of the PRNG seeded with randomness obtained from
/// the OS RNG (using the [`getrandom` crate]).
///
/// The PRNG is not portable/reproducible though, meaning that the output given
/// the same seeding material may differ between platforms and versions. In
/// particular, the output depends on the targets endianness and the version
/// number of this crate. If you need a PRNG that is deterministic and portable,
/// and don't need the ability to reseed, use a standard XOF, like SHAKE256.
///
/// [`getrandom` crate]: https://crates.io/crates/getrandom
pub struct RngState {
    state: InternalState,
}

impl RngState {
    /// Apply keccak-f\[1600\] to the state.
    fn apply_f(&mut self) {
        self.state.apply_f();
    }

    // The four basic actions

    // The following two functions implement the basic action "input".
    // `absorb_partial_block_padded` handles the case where padding is neccessary
    // (i.e. the last input chunk) and `absorb_block` handles intermediate full
    // chunks

    /// Absorb a partial block `block` of < `RATE_BYTES` bytes, applying proper
    /// padding and running the permutation.
    ///
    /// The padding is written directly into the state to avoid copying the
    /// input `block` to a larger buffer.
    ///
    /// # Panics
    /// Panics if the following condition is violated: `block.len() <
    /// RATE_BYTES`.
    #[inline]
    fn absorb_partial_block_padded(&mut self, block: &[u8]) {
        assert!(block.len() < RATE_BYTES);
        let rate_state = self.state.get_rate_bytes_mut();
        for (b, s) in block.iter().zip(rate_state.iter_mut()) {
            *s ^= b;
        }
        rate_state[block.len()] ^= 0b10000000;
        rate_state[RATE_BYTES - 1] ^= 0b00000001;
        self.apply_f();
    }

    /// Absorb a full block `block` of precisely `RATE_BYTES` bytes, running the
    /// permutation.
    fn absorb_block(&mut self, block: &[u8; RATE_BYTES]) {
        for (b, s) in block.iter().zip(self.state.get_rate_bytes_mut().iter_mut()) {
            *s ^= b;
        }
        self.apply_f();
    }

    /// Basic action "initial-output".
    ///
    /// First output the bytes in the "rate area" as random output bytes, by
    /// writing them to `dest`. Then apply keccak-f.
    fn basic_initial_output(&mut self, dest: &mut [u8]) {
        let len = core::cmp::min(dest.len(), RATE_BYTES);
        let block = &mut dest[..len];
        block.copy_from_slice(&self.state.get_rate_bytes()[..len]);
        self.apply_f();
    }

    /// Basic action "intermediate-output".
    ///
    /// First output the bytes in the "rate area" and "zeroized capacity area"
    /// as random output bytes, by writing them to `dest`. Then apply
    /// keccak-f.
    fn basic_intermediate_output(&mut self, dest: &mut [u8]) {
        let len = core::cmp::min(dest.len(), RATE_BYTES + CAPACITY_BYTES);
        let block = &mut dest[..len];
        block.copy_from_slice(&self.state.get_rate_zeroized_capacity_bytes()[..len]);
        self.apply_f();
    }

    /// Basic action "make-forward-secure".
    ///
    /// Zeroize (i.e., fill with zero/null bytes) the "zeroized capacity area".
    /// Doing this after an application of the permutation makes inverting the
    /// permutation impossible, therefore establishing forward secrecy.
    ///
    /// If the state is leaked after this action then an attacker won't be able
    /// to infer inputs to or outputs from the RNG performed before this action.
    fn basic_make_forward_secure(&mut self) {
        self.state.zeroize_for_forward_security()
    }

    // Higher level user interface

    /// (Re)seed the RNG with data `seed`. `seed` can be of arbitrary length.
    /// With high entropy data, i.e. (almost) uniform random bytes, you need *at
    /// least* 16 bytes of data to properly seed the RNG.
    pub fn seed(&mut self, seed: &[u8]) {
        let mut blocks = seed.chunks_exact(RATE_BYTES);
        for block in &mut blocks {
            self.absorb_block(block.try_into().unwrap());
        }
        // handle remainder with padding
        self.absorb_partial_block_padded(blocks.remainder());
    }

    /// Call the closure `f` with a buffer of 64 bytes, then (re)seed the RNG
    /// using the data written to the buffer.
    ///
    /// The buffer will be zeroized so the secret seeding material is not left
    /// in memory.
    ///
    /// 64 bytes (512 bits) can be absorbed into the state with a single call to
    /// keccak-f, so this function gives a convenient, fast and secure way to
    /// seed the RNG.
    pub fn seed_with_64<E, F: FnOnce(&mut [u8]) -> Result<(), E>>(
        &mut self,
        f: F,
    ) -> Result<(), E> {
        let mut buffer = zeroize::Zeroizing::new([0u64; 8]);
        f(u64_slice_as_ne_bytes_mut(buffer.as_mut()))?;
        self.absorb_partial_block_padded(u64_slice_as_ne_bytes(buffer.as_ref()));
        Ok(())
    }

    /// (Re)seed the RNG with data from the OS RNG (e.g. the `getrandom` syscall
    /// in linux). This should be the preferred method to (re)seed the RNG.
    #[cfg(feature = "getrandom")]
    #[cfg_attr(doc, doc(cfg(feature = "getrandom")))]
    pub fn seed_with_getrandom(&mut self) -> Result<(), getrandom::Error> {
        self.seed_with_64(getrandom::getrandom)
    }

    /// Create a new unseeded instance of the RNG. You MUST seed the RNG, e.g.
    /// using [`Self::seed_with_getrandom`], before use, otherwise the output is
    /// not random at all! Use [`Self::new_from_getrandom`] to create an already
    /// seeded instance of the RNG.
    pub fn new_unseeded() -> Self {
        let mut rng = Self {
            state: InternalState::new(),
        };
        const DIVERSIFIER: &[u8; 80] =
            b"FAST ERASURE KECCAK SPONGE/DUPLEX PRNG\0RUST CRATE fast-erasure-shake-rng 0.1.0\0\0";
        rng.seed(DIVERSIFIER.as_ref());
        rng
    }

    /// Create a new instance of the RNG, seeded with entropy from the OS RNG.
    /// This should be the preferred method to create an instance of the RNG.
    #[cfg(feature = "getrandom")]
    #[cfg_attr(doc, doc(cfg(feature = "getrandom")))]
    pub fn new_from_getrandom() -> Result<Self, getrandom::Error> {
        let mut rng = Self::new_unseeded();
        rng.seed_with_getrandom()?;
        Ok(rng)
    }

    /// Fill `dest` with random bytes. The RNG MUST be seeded prior to using
    /// this method.
    pub fn fill_random_bytes(&mut self, mut dest: &mut [u8]) {
        self.basic_initial_output(dest);
        if dest.len() > RATE_BYTES {
            dest = &mut dest[RATE_BYTES..];

            loop {
                self.basic_intermediate_output(dest);
                if dest.len() <= RATE_BYTES + CAPACITY_BYTES {
                    break;
                }
                dest = &mut dest[RATE_BYTES + CAPACITY_BYTES..];
            }
        }

        self.basic_make_forward_secure();
    }

    /// Output an array `[u8; N]` filled with random bytes. The RNG MUST be
    /// seeded prior to using this method.
    pub fn get_random_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        self.fill_random_bytes(&mut out);
        out
    }
}

#[cfg(feature = "rand-core")]
mod rand_core {
    use super::{u64_slice_as_ne_bytes, u64_slice_as_ne_bytes_mut, RngState};
    use rand_core::RngCore;

    #[cfg_attr(doc, doc(cfg(feature = "rand_core")))]
    impl RngCore for RngState {
        /// Very slow due to fast erasure. Don't use.
        fn next_u32(&mut self) -> u32 {
            // just truncate an `u64`
            #[allow(clippy::cast_possible_truncation)]
            let res = self.next_u64() as u32;
            res
        }

        /// Very slow due to fast erasure. Don't use.
        fn next_u64(&mut self) -> u64 {
            let buf: [u8; 8] = self.get_random_bytes();
            u64::from_ne_bytes(buf)
        }

        /// Equivalent to [`Self::fill_random_bytes`].
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.fill_random_bytes(dest)
        }

        /// Equivalent to [`Self::fill_random_bytes`]. Always returns succes
        /// (`Ok(())`).
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_random_bytes(dest);
            Ok(())
        }
    }

    #[cfg_attr(doc, doc(cfg(feature = "rand_core")))]
    impl rand_core::CryptoRng for RngState {}

    #[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
    pub struct Seed([u64; 8]);

    impl AsRef<[u8]> for Seed {
        fn as_ref(&self) -> &[u8] {
            u64_slice_as_ne_bytes(self.0.as_ref())
        }
    }

    impl AsMut<[u8]> for Seed {
        fn as_mut(&mut self) -> &mut [u8] {
            u64_slice_as_ne_bytes_mut(self.0.as_mut())
        }
    }

    impl From<[u64; 8]> for Seed {
        fn from(other: [u64; 8]) -> Self {
            Self(other)
        }
    }

    impl zeroize::Zeroize for Seed {
        fn zeroize(&mut self) {
            self.0.zeroize()
        }
    }

    impl Drop for Seed {
        fn drop(&mut self) {
            zeroize::Zeroize::zeroize(self)
        }
    }

    impl zeroize::ZeroizeOnDrop for Seed {}

    #[cfg_attr(doc, doc(cfg(feature = "rand_core")))]
    impl rand_core::SeedableRng for RngState {
        type Seed = Seed;

        /// No good reason to use this instead of [`Self::seed`].
        fn from_seed(seed: Self::Seed) -> Self {
            let mut rng = Self::new_unseeded();
            rng.absorb_partial_block_padded(seed.as_ref());
            rng
        }

        /// An `u64` doesn't give enough entropy. Don't use!
        fn seed_from_u64(state: u64) -> Self {
            // A PCG32 is not going to help here. Keccak is secure; the problem is that this
            // seed is way to small (can't contain enough entropy).
            let mut rng = Self::new_unseeded();
            rng.absorb_partial_block_padded(state.to_ne_bytes().as_ref());
            rng
        }

        /// Create instance of this PRNG seeded with output from `rng`. `rng`
        /// should be a cryptographically secure RNG, for example the OS RNG.
        ///
        /// To seed from the OS RNG use the more convenient
        /// [`Self::new_from_getrandom`].
        fn from_rng<R: rand_core::RngCore>(mut seeder_rng: R) -> Result<Self, rand_core::Error> {
            // Don't leave a copy of the seeding material.
            let mut rng = Self::new_unseeded();
            rng.seed_with_64(|buf| seeder_rng.try_fill_bytes(buf))?;
            Ok(rng)
        }

        /// Same as [`Self::new_from_getrandom`], but panics on error.
        ///
        /// # Panics
        /// If the call to the OS RNG (e.g. the `getrandom` syscall on linux)
        /// fails.
        #[cfg(feature = "getrandom")]
        fn from_entropy() -> Self {
            Self::new_from_getrandom().expect("from_entropy failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RngState;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    #[test]
    fn create_and_seed() {
        let mut rng = RngState::new_unseeded();
        rng.seed(b"HELLO WORLD");
        let out1 = rng.get_random_bytes::<32>();
        let out2 = rng.get_random_bytes::<32>();
        // probability of two subsequent 32 byte outputs to be equal is approximately 0
        // (2^-512)
        assert_ne!(out1, out2);
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn create_from_getrandom() {
        let mut rng = RngState::new_from_getrandom().expect("error in getrandom");
        let out1 = rng.get_random_bytes::<32>();
        let out2 = rng.get_random_bytes::<32>();
        // probability of two subsequent 32 byte outputs to be equal is approximately 0
        // (2^-512)
        assert_ne!(out1, out2);
    }

    #[cfg(feature = "rand_core")]
    #[test]
    fn rand_core_from_seed() {
        let seed = [37u64; 8].into();
        let mut rng = RngState::from_seed(seed);
        let mut buf = [0; 15];
        rng.try_fill_bytes(&mut buf).expect("unreachable");
        assert_ne!(buf, [0; 15]);
    }
}
