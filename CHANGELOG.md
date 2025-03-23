# Changelog

### 0.3.0 - 2025-03-23
### Changed
- **Breaking:** Rename `RngState::seed_with_64` to `RngState::try_seed_with_64`
  and add new `RngState::seed_with_64` for infallible seed functions.
- **Breaking:** Update public `rand_core` dependency to version `0.9`.
- **Breaking:** Update public `getrandom` dependency to version `0.3`.

## 0.2.0 - 2022-09-06
### Added
- Properly document how the RNG works.

### Changed
- Use the intermediate results in the "zeroized capacity area" as RNG output.
  This improves performance for large requests (which require multiple calls to
  the keccak-f permutation).

## 0.1.0 - 2022-05-27
Initial version
