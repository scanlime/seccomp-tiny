use core::fmt;
use core::convert::TryInto;
use crate::abi::*;
use crate::bpf::*;
use crate::seccomp;

#[derive(Clone, Eq, PartialEq)]
pub struct ProgramBuffer {
    len: u16,
    array: [SockFilter; BPF_MAXINSNS],
}

impl ProgramBuffer {
    pub fn new() -> Self {
        const EMPTY: SockFilter = SockFilter {
            code: 0, k: 0, jt: 0, jf: 0
        };
        ProgramBuffer {
            len: 0,
            array: [ EMPTY; BPF_MAXINSNS ]
        }
    }
    
    pub fn instructions(&self) -> &[SockFilter] {
        &self.array[.. self.len as usize]
    }

    pub fn activate(&self) {
        let prog = SockFilterProg::new(self.instructions());
        if let Err(result) = seccomp::activate(&prog) {
            panic!("seccomp setup error ({})", result);
        }
    }
    
    pub fn block(&mut self, block: &[SockFilter]) {
        for instruction in block {
            self.inst(*instruction);
        }
    }

    pub fn inst(&mut self, instruction: SockFilter) {
        if self.len as usize == BPF_MAXINSNS {
            panic!("filter program exceeding size limit");
        }
        self.array[self.len as usize] = instruction;
        self.len += 1;
    }
    
    pub fn if_eq(&mut self, k: usize, block: &[SockFilter]) {
        let to_end_of_block: u8 = block.len().try_into().unwrap();
        self.inst(jump( BPF_JMP+BPF_JEQ+BPF_K, k as u32, 0, to_end_of_block ));
        self.block(block);
    }

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for index in 0 .. self.len {
            write!(f, "{:04} {:?}\n",
                   index, self.array[index as usize])?;
        }
        Ok(())
    }
}

