use crate::abi::*;
use core::marker::PhantomData;
use sc::syscall;

impl SockFilterProg<'_> {
    pub fn new<'a>(instructions: &'a [SockFilter]) -> SockFilterProg<'a> {
        assert!(instructions.len() <= BPF_MAXINSNS);
        SockFilterProg {
            len: instructions.len() as u16,
            filter: instructions.as_ptr(),
            phantom: PhantomData
        }
    }
}

pub fn activate(program: &SockFilterProg) -> Result<(), isize> {
    let ptr = program as *const SockFilterProg as usize;
    match unsafe {
        syscall!(PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        syscall!(PRCTL, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ptr, 0, 0) as isize
    } {
        0 => Ok(()),
        errno => Err(errno),
    }
}
