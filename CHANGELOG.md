# Changelog

## 0.2.0 - 2022-09-06
### Added
- Proper documentation of how the RNG works.

### Changed
- Use the intermediate results in the "zeroized capacity area" as RNG output.
  This improves performance for large requests (which require multiple calls to
  the keccak-f permutation).

## 0.1.0 - 2022-05-27
Initial version
