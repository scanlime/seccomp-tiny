//! Tiny Seccomp
//! -------------
//!
//! Sometimes you need a syscall filter without an entire dynamic
//! library. Or std. Or an allocator. Whatever! Just throw some
//! instructions in a buffer, we can do it.
//!
//! This crate does not include any kind of optimizer or compiler
//! for building BPF filters, but it has some basic syntax for
//! constructing them manually in a mostly unpainful way without
//! any allocations.
//!
//! You can use the lower-level pieces of this crate on their
//! own if you like, but the easiest way to get started is to
//! add instructions or blocks of instructions to a
//! seccomp_tiny::ProgramBuffer and then call its method
//! seccomp_tiny::ProgramBuffer::activate() to irrevocably
//! apply the filter and panic on failure.
//!
//! ```
//! use std;
//! use seccomp_tiny::{ProgramBuffer, bpf, abi};
//! let mut p = ProgramBuffer::new();
//! p.inst( bpf::ret( abi::SECCOMP_RET_ALLOW ) );
//! p.activate()
//! ```

#![no_std]

#[cfg(not(any(target_os = "linux", target_os = "android")))]
compile_error!("seccomp only works on linux or android");

mod buffer;
mod seccomp;

pub mod abi;
pub mod bpf;

pub use buffer::ProgramBuffer;
pub use seccomp::activate;
