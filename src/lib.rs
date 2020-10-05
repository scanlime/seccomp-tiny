#![no_std]

#[cfg(not(any(target_os = "linux", target_os = "android")))]
compile_error!("seccomp only works on linux or android");

mod buffer;
mod seccomp;

pub mod abi;
pub mod bpf;

pub use buffer::ProgramBuffer;
pub use seccomp::activate;
