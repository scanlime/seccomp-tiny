//! BPF programming utilities
//! --------------------------
//!
//! These are functions for building fragments of low-level
//! BPF (Berkeley Packet Filter) code, used for making system
//! call filtering decisions in seccomp.

use crate::abi::*;

/// Build a BPF statement with one 32-bit parameter.
///
/// This is suitable for building any instruction other than conditional
/// jumps, which have additional jump target fields.
pub const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, k, jt: 0, jf: 0 }
}

/// Build any BPF statement including conditional jumps.
///
/// This is equivalent to constructing a SockFilter from its parts.
pub const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, k, jt, jf }
}

/// Build an unconditional jump instruction.
///
/// In BPF, jumps always go forward, loops are not possible. The parameter
/// is a count of instructions to skip. This is equivalent
/// to `stmt( BPF_JMP + BPF_JA, k )`.
pub const fn jump_always(k: u32) -> SockFilter {
    stmt( BPF_JMP+BPF_JA, k )
}

/// Build an instruction to load a 32-bit immediate value into the accumulator.
///
/// This is equivalent to `stmt( BPF_LD + BPF_W + BPF_IMM, k )`.
pub const fn imm(k: u32) -> SockFilter {
    stmt( BPF_LD+BPF_W+BPF_IMM, k )
}

/// Build an instruction to return a 32-bit constant value.
///
/// This is equivalent to `stmt( BPF_RET + BPF_K, k )`
pub const fn ret(k: u32) -> SockFilter {
    stmt( BPF_RET+BPF_K, k )
}

/// Build an instruction to load a 32-bit value from a constant address.
///
/// This is equivalent to `stmt( BPF_LD + BPF_W + BPF_ABS, k )`
pub const fn load(k: usize) -> SockFilter {
    stmt( BPF_LD+BPF_W+BPF_ABS, k as u32 )
}

/// Build an instruction to store a 32-bit value at a constant address.
///
/// This is equivalent to `stmt( BPF_ST, k )`
pub const fn store(k: usize) -> SockFilter {
    stmt( BPF_ST, k as u32 )
}
