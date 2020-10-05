use core::fmt;
use core::convert::TryInto;
use crate::abi::*;
use crate::bpf::*;
use crate::seccomp;

/// Fixed size buffer for building seccomp BPF programs
///
/// Conceptually this is like a Vec<SockFilter>, but to keep compatibility with `no_std` and
/// take advantage of the small maximum length of a BPF program, this type features a fixed
/// size array that can hold the maximum (4096) instructions.
///
/// ```
/// use sc::nr;
/// use seccomp_tiny::{ProgramBuffer, abi, bpf::ret};
///
/// let mut p = ProgramBuffer::new();
///
/// p.if_any_eq(&[
///     nr::ARCH_PRCTL,
///     nr::PRCTL,
///     nr::WAITID,
///     nr::PTRACE,
///     nr::KILL,
/// ], &[
///     ret(abi::SECCOMP_RET_ALLOW)
/// ]);
///
/// p.inst(ret(abi::SECCOMP_RET_TRACE));
///
/// println!("{:?}", p);
/// ```
///
#[derive(Clone, Eq, PartialEq)]
pub struct ProgramBuffer {
    len: u16,
    array: [SockFilter; BPF_MAXINSNS],
}

impl ProgramBuffer {
    /// Construct a new empty ProgramBuffer
    pub fn new() -> Self {
        const EMPTY: SockFilter = SockFilter {
            code: 0, k: 0, jt: 0, jf: 0
        };
        ProgramBuffer {
            len: 0,
            array: [ EMPTY; BPF_MAXINSNS ]
        }
    }

    /// Returns a slice referring to all SockFilter instructions added to the buffer
    pub fn instructions(&self) -> &[SockFilter] {
        &self.array[.. self.len as usize]
    }

    /// Activate the seccomp program, panic on error.
    ///
    /// This is equivalent to:
    /// ```
    /// # use seccomp_tiny::{ProgramBuffer, abi, bpf};
    /// # let mut buffer = ProgramBuffer::new();
    /// # buffer.inst(bpf::ret(abi::SECCOMP_RET_ALLOW));
    ///
    /// let prog = abi::SockFilterProg::new(buffer.instructions());
    /// let result = seccomp_tiny::activate(&prog);
    /// if let Err(code) = result {
    ///     panic!("... {}", code);
    /// }
    /// ```
    pub fn activate(&self) {
        let prog = SockFilterProg::new(self.instructions());
        if let Err(result) = seccomp::activate(&prog) {
            panic!("seccomp setup error ({})", result);
        }
    }

    /// Copy a slice of SockFilter instructions to the end of the buffer
    ///
    /// Panics on buffer full.
    pub fn block(&mut self, block: &[SockFilter]) {
        for instruction in block {
            self.inst(*instruction);
        }
    }

    /// Copy a SockFilter instruction to the end of the buffer
    ///
    /// Panics on buffer full.
    pub fn inst(&mut self, instruction: SockFilter) {
        if self.len as usize == BPF_MAXINSNS {
            panic!("filter program exceeding size limit");
        }
        self.array[self.len as usize] = instruction;
        self.len += 1;
    }

    /// Build a conditional instruction block
    ///
    /// This copies a group of SockFilter instructions to the end of the buffer,
    /// gated by a conditional jump such that the block runs if the accumulator
    /// matches the value `k`.
    ///
    /// Panics if the buffer is full, or the block we are adding is larger
    /// than the reach of a single jump (256 instructions).
    pub fn if_eq(&mut self, k: usize, block: &[SockFilter]) {
        let to_end_of_block: u8 = block.len().try_into().unwrap();
        self.inst(jump( BPF_JMP+BPF_JEQ+BPF_K, k as u32, 0, to_end_of_block ));
        self.block(block);
    }

    /// Build a conditional block that checks multiple values
    ///
    /// This is similar to making repeated calls to if_eq(), however the block
    /// of code is only included once. This generates a series of conditional
    /// jump instructions which test each value in `k_list`, and another jump
    /// which skips the block if none of the values have matched.
    ///
    /// Panics if the buffer is full, or if either the list of values
    /// or the instruction block are too large to jump past at once (256
    /// instructions each).
    pub fn if_any_eq(&mut self, k_list: &[usize], block: &[SockFilter]) {
        let mut to_block: u8 = k_list.len().try_into().unwrap();
        for k in k_list {
            self.inst(jump( BPF_JMP+BPF_JEQ+BPF_K, *k as u32, to_block, 0 ));
            to_block -= 1;
        }        
        self.inst(jump_always(block.len().try_into().unwrap()));
        self.block(block);
    }
}

impl fmt::Debug for ProgramBuffer {
    /// Format a ProgramBuffer as a list of instructions, one per line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for index in 0 .. self.len {
            write!(f, "{:04} {:?}\n",
                   index, self.array[index as usize])?;
        }
        Ok(())
    }
}
