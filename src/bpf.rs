use crate::abi::*;

pub const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, k, jt: 0, jf: 0 }
}

pub const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, k, jt, jf }
}

pub const fn jump_always(k: u32) -> SockFilter {
    stmt( BPF_JMP+BPF_JA, k )
}

pub const fn imm(k: u32) -> SockFilter {
    stmt( BPF_LD+BPF_W+BPF_IMM, k )
}

pub const fn ret(k: u32) -> SockFilter {
    stmt( BPF_RET+BPF_K, k )
}

pub const fn load(k: usize) -> SockFilter {
    stmt( BPF_LD+BPF_W+BPF_ABS, k as u32 )
}

pub const fn store(k: usize) -> SockFilter {
    stmt( BPF_ST, k as u32 )
}
