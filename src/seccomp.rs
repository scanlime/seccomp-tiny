use crate::abi::*;
use core::marker::PhantomData;
use sc::syscall;

impl SockFilterProg<'_> {
    /// Construct a new SockFilterProg from a SockFilter slice
    ///
    /// A [`SockFilterProg`] is part of the kernel's ABI that acts
    /// like a wrapper around a &[SockFilter] slice. This
    /// constructor accepts such a slice, and returns a
    /// SockFilterProg which maintains a reference to that slice.
    pub fn new<'a>(instructions: &'a [SockFilter]) -> SockFilterProg<'a> {
        assert!(instructions.len() <= BPF_MAXINSNS);
        SockFilterProg {
            len: instructions.len() as u16,
            filter: instructions.as_ptr(),
            phantom: PhantomData
        }
    }
}

/// Try to activate a seccomp program, returning the error code on failure.
///
/// If you are looking for the slightly higher level version, see
/// [`crate::ProgramBuffer::activate()`].
///
/// See the documentation for prctl's PR_SET_SECCOMP for detailed reasons
/// why this may fail, and the error codes it may return.
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
