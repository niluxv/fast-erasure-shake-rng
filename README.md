# fast-erasure-shake-rng ![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue) [![fast-erasure-shake-rng on crates.io](https://img.shields.io/crates/v/fast-erasure-shake-rng)](https://crates.io/crates/fast-erasure-shake-rng) [![Source Code Repository](https://img.shields.io/badge/Code-On%20GitHub-blue?logo=GitHub)](https://github.com/niluxv/fast-erasure-shake-rng)

A cryptographically secure fast erasure (i.e. forward secure) pseudo-random number generator, based on the sponge/duplex construction and the keccak-*f* permutation.

Prioritizes security above performance (speed).


## Usage

To create an instance of the RNG, preferably use [`RngState::new_from_getrandom`][__link0]. You can hash in additional data using [`RngState::seed`][__link1] if wanted. To generate random data use [`RngState::fill_random_bytes`][__link2] to fill a buffer with random bytes, or [`RngState::get_random_bytes`][__link3] to obtain an array filled with random bytes. The RNG can always be reseeded (if you want backward security) using [`RngState::seed_with_getrandom`][__link4].


## Examples

Basic usage:


```rust
use fast_erasure_shake_rng::RngState;

let mut rng = RngState::new_from_getrandom().unwrap();
let key = rng.get_random_bytes::<32>();
```

Reseeding for backward security:


```rust
use fast_erasure_shake_rng::RngState;

let mut rng = RngState::new_from_getrandom().unwrap();
let key1 = rng.get_random_bytes::<32>();
// do other things ...
// later:
rng.seed_with_getrandom().unwrap();
let key2 = rng.get_random_bytes::<1000>();
```

Hashing in additional data, to reduce reliance on the OS RNG:


```rust
use fast_erasure_shake_rng::RngState;

let mut rng = RngState::new_from_getrandom().unwrap();
let mut user_dice_rolls = String::new();
std::io::stdin().read_line(&mut user_dice_rolls).unwrap();
rng.seed(user_dice_rolls.as_ref());

let key = rng.get_random_bytes::<32>();
```


## Determinism & Portability

This PRNG is deterministic, meaning that it gives the same output when seeded with the same input(s). Therefore it is necessary to seed it with a non-deterministic source of randomness. The [`RngState::new_from_getrandom`][__link5] method crates an instance of the PRNG seeded with randomness obtained from the OS RNG (using the [`getrandom` crate][__link6]).

The PRNG is not portable/reproducible though, meaning that the output given the same seeding material may differ between platforms and versions. In particular, the output depends on the targets endianness and the version number of this crate. If you need a PRNG that is deterministic and portable, and don’t need the ability to reseed, use a standard XOF, like SHAKE256.


## Crate Features

 - `getrandom` (default): Enable dependency on the [`getrandom` crate][__link7]. This enables convenient and secure ways to seed the RNG, e.g. [`RngState::new_from_getrandom`][__link8].
 - `rand-core`: Enable dependency on the [`rand_core` crate][__link9]. This enables implementations of the Rng traits from `rand_core` for [`RngState`][__link10].


## RNGs and Cryptography Notes


### Attacker controlled entropy sources

There is a widespread idea that adding as many entropy sources as possible to an RNG is always a good idea. Unfortunately, life is not that easy. If an entropy source is attacker controlled, it can actually be used to weaken or break the RNG. This does require the malicious entropy source to know or guess the input from other (earlier added) entropy sources, or know the RNG state (i.e. the randomness pool). While this is not a mild assumption, it is more conceivable for the malicious entropy source to have access to these inputs than for the attacker himself to have them. Therefore it is still a good idea to be a bit careful with adding entropy sources. See e.g. <https://blog.cr.yp.to/20140205-entropy.html> for more information.


### Backward security

This RNG allows for reseeding, i.e. hash extra entropy into the state (after initial use). This would provide backward security: even if an attacker has observed the RNG state in the past, he won’t be able to predict the output of the RNG after the reseed operation has happend. In practice though, if an attacker is able to see the RNG state you have much worse problems then RNG security if you want to perform crypto. Hence there is little to no reason to actually reseed the RNG after some time.


## Design

I initially thought that just a sponge/duplex construction over some (secure) permutation, would yield a secure RNG, but unfortunately that construction is not forward secure. The problem is that the used permutation, keccak-f[1600] is efficiently invertible. Hence if no reseed is performed after obtaining random bytes, an attacker that obtained the final state of the RNG could just apply the inverse permutation repeatedly to find all the bytes that were emitted since the last reseed.

What makes the sponge construction still secure for a hash function or XOF is that the bytes in the capacity part of the state are never published, unlike what we have to assume for forward security of the RNG. What would solve the problem is to zeroize the capacity part of the state after every permutation application. But then the RNG doesn’t maintain a secret entropy pool: given only one rate sized output, one could compute all future values until a reseed. Hence we actually need two separate capacity parts in the state: one which is always (that is, every time after outputting random bytes) zeroized for forward secrecy and one that acts as the usual (entropy collecting) state part.


## TODOs
 - [ ] improve throughput for large requests by utilizing intermediate results in the "zeroized state part"
 - [ ] add a fast-erasure buffered mode for more efficient frequent small requests


## Changelog
See `CHANGELOG.md`.


## Documentation
The API documentation of `fast-erasure-shake-rng` is available at <https://docs.rs/secmem-alloc/*/fast_erasure_shake_rng/>.


 [__cargo_doc2readme_dependencies_info]: ggGkYW0AYXSEG-du7JIOwYWSG5U5bAOjAt7nG_7aQsEpZ_doGxAj2Q47y74hYXKEG80F21da3ZJ7G05Nj8KMiQkZG6HP-Vm-U1aWG6HaflbRPrjAYWSBg3ZmYXN0LWVyYXN1cmUtc2hha2Utcm5nZTAuMS4wdmZhc3RfZXJhc3VyZV9zaGFrZV9ybmc
 [__link0]: https://docs.rs/fast-erasure-shake-rng/0.1.0/fast_erasure_shake_rng/?search=fast_erasure_shake_rng::RngState::new_from_getrandom
 [__link1]: https://docs.rs/fast-erasure-shake-rng/0.1.0/fast_erasure_shake_rng/?search=fast_erasure_shake_rng::RngState::seed
 [__link10]: https://docs.rs/fast-erasure-shake-rng/0.1.0/fast_erasure_shake_rng/?search=fast_erasure_shake_rng::RngState
 [__link2]: https://docs.rs/fast-erasure-shake-rng/0.1.0/fast_erasure_shake_rng/?search=fast_erasure_shake_rng::RngState::fill_random_bytes
 [__link3]: https://docs.rs/fast-erasure-shake-rng/0.1.0/fast_erasure_shake_rng/?search=fast_erasure_shake_rng::RngState::get_random_bytes
 [__link4]: https://docs.rs/fast-erasure-shake-rng/0.1.0/fast_erasure_shake_rng/?search=fast_erasure_shake_rng::RngState::seed_with_getrandom
 [__link5]: https://docs.rs/fast-erasure-shake-rng/0.1.0/fast_erasure_shake_rng/?search=fast_erasure_shake_rng::RngState::new_from_getrandom
 [__link6]: https://crates.io/crates/getrandom
 [__link7]: https://crates.io/crates/getrandom
 [__link8]: https://docs.rs/fast-erasure-shake-rng/0.1.0/fast_erasure_shake_rng/?search=fast_erasure_shake_rng::RngState::new_from_getrandom
 [__link9]: https://crates.io/crates/rand_core

