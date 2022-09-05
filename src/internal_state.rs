use crate::{u64_slice_as_ne_bytes, u64_slice_as_ne_bytes_mut, CAPACITY_LANES, LANES, RATE_LANES};

/// The keccak-f\[1600\] = keccack-*p*\[1600, 24\] permutation.
fn keccak_f1600(state: &mut [u64; LANES]) {
    keccak::f1600(state);
}

/// The internal state of the RNG. This is a 1600 bit Keccak state.
///
/// The state is divided into three "areas", see the top level documentation.
/// The API of this struct does not allow acces to the "capacity area". It does
/// offer read/write acces to the "rate area", read acces to the union of the
/// "rate area" and the "zeroized capacity area", the ability to zeroize the
/// "zeroized capacity area". Finally the keccak-f\[1600\] permutation can be
/// applied to the whole state.
pub(crate) struct InternalState {
    state: [u64; LANES],
}

impl InternalState {
    /// Apply keccak-f\[1600\] to the state.
    pub(crate) fn apply_f(&mut self) {
        keccak_f1600(&mut self.state);
    }

    /// Zeroize the "zeroized capacity area" part of the state. Doing this after
    /// an application of the permutation makes inverting the permutation
    /// impossible, therefore establishing forward secrecy.
    pub(crate) fn zeroize_for_forward_security(&mut self) {
        use zeroize::Zeroize;

        self.state[RATE_LANES..RATE_LANES + CAPACITY_LANES].zeroize()
    }

    /// Get the "rate area" of the state as a slice. Result depends on
    /// endianness.
    pub(crate) fn get_rate_bytes(&self) -> &[u8] {
        u64_slice_as_ne_bytes(&self.state[..RATE_LANES])
    }

    /// Get the "rate area" of the state as a mutable slice. Result depends on
    /// endianness.
    pub(crate) fn get_rate_bytes_mut(&mut self) -> &mut [u8] {
        u64_slice_as_ne_bytes_mut(&mut self.state[..RATE_LANES])
    }

    /// Get the "rate area" plus the "zeroized capacity area" of the state as a
    /// single slice. Result depends on endianness.
    pub(crate) fn get_rate_zeroized_capacity_bytes(&self) -> &[u8] {
        u64_slice_as_ne_bytes(&self.state[..RATE_LANES + CAPACITY_LANES])
    }

    /// Create a new empty state.
    pub(crate) fn new() -> Self {
        Self { state: [0; LANES] }
    }
}
