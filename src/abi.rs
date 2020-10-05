// prctl
// linux/include/uapi/linux/prctl.h
pub const PR_SET_NO_NEW_PRIVS: usize = 38;
pub const PR_SET_SECCOMP: usize = 22;
pub const SECCOMP_MODE_FILTER: usize = 2;

// sock_fprog
// seccomp(2)
#[derive(Debug)]
#[repr(C)]
pub struct SockFilterProg<'a> {
    pub len: u16,
    pub filter: *const SockFilter,
    pub phantom: core::marker::PhantomData<&'a SockFilter>
}

// sock_filter
// seccomp(2)
// linux/include/uapi/linux/filter.hOB
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// seccomp_data
// seccomp(2)
#[derive(Debug)]
#[repr(C)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6]
}

// seccomp filter return values
// linux/include/uapi/linux/seccomp.h
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x00000000;
pub const SECCOMP_RET_TRAP: u32 = 0x00030000;
pub const SECCOMP_RET_ERRNO: u32 = 0x00050000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff00000;
pub const SECCOMP_RET_LOG: u32 = 0x7ffc0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

// bpf instruction classes
// linux/include/uapi/linux/bpf_common.h
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISX: u16 = 0x07;

// bpf data width
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;
pub const BPF_DW: u16 = 0x18;

// bpf data modes
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xa0;

// bpf source field
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

// bpf jump codes
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;

// bpf alu operations
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_MOD: u16 = 0x90;
pub const BPF_XOR: u16 = 0xa0;

pub const BPF_MAXINSNS: usize = 4096;

