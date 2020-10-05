#![no_std]
#![no_main]
#![feature(panic_info_message)]
#![feature(lang_items)]

#[macro_use]
extern crate memoffset;
    
use sc::{syscall, nr};
use seccomp_tiny::{ProgramBuffer, abi, bpf::load, bpf::ret};

fn example_main() {

    println!("Hi, this is the beginning of the program.");

    // This should be harmless normally; to demonstrate:
    unsafe { syscall!(SCHED_YIELD) };
    
    // Start to build a seccomp BPF program
    let mut p = ProgramBuffer::new();

    // Keep syscall in the accumulator generally.
    // Programs can also inspect integer syscall arguments.
    p.inst(load(offset_of!(abi::SeccompData, nr)));

    // Match against the accumulator (syscall number) and kill the process if anyone tries 'uname'
    p.if_eq(nr::UNAME, &[ ret(abi::SECCOMP_RET_KILL_PROCESS) ]);

    // As an example, we could stop there and apply the filter and carry on...
    p.inst(ret(abi::SECCOMP_RET_ALLOW));

    println!("About to apply the first seccomp filter");
    p.activate();
    println!("okay");
    
    // But in this case let's install another program right away. Both will be active, and the
    // kernel applies the most restrictive policy of all active programs.
    let mut p = ProgramBuffer::new();
    p.inst(load(offset_of!(abi::SeccompData, nr)));

    // We can match a list of syscalls at once
    p.if_any_eq(&[
        nr::UNAME,
        nr::NANOSLEEP,
        nr::SCHED_YIELD,
        nr::BRK,
    ], &[
        // This could be a longer group of instructions too, with nested conditionals examining args
        ret(abi::SECCOMP_RET_TRAP)
    ]);

    // For this example the policy defaults to 'allow' but in a real security sandbox that would be bad.
    p.inst(ret(abi::SECCOMP_RET_ALLOW));

    println!("About to apply the second filter.");
    p.activate();
    println!("okay.");

    println!("about to try causing a trap on purpose");
    unsafe { syscall!(SCHED_YIELD) };
}

/*
 * The rest of this is not relevant directly to the example,
 * but we want to be able to have an entry point and stderr.
 */

use core::panic::PanicInfo;
use core::fmt::{self, Write};

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        let mut stderr = $crate::SysFd(2);
        drop(core::fmt::write(&mut stderr, core::format_args!( $($arg)* )));
    });
}

#[macro_export]
macro_rules! println {
    () => ({
        print!("\n");
    });
    ($($arg:tt)*) => ({
        print!( $($arg)* );
        println!();
    });
}

#[derive(Debug)]
pub struct SysFd(pub u32);

impl fmt::Write for SysFd {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if s.len() == unsafe { syscall!(WRITE, self.0, s.as_ptr() as usize, s.len()) } {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

pub fn exit(code: usize) -> ! {
    unsafe { syscall!(EXIT, code) };
    unreachable!()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut stderr = SysFd(2);
    if let Some(args) = info.message() {
        drop(fmt::write(&mut stderr, *args));
    }
    drop(write!(&mut stderr, "\npanic!\n"));
    exit(128)
}

// This is the real entry point invoked by startup.S
#[no_mangle]
fn __libc_start_main(_main: usize, _argc: isize, _argv: *const *const u8) -> isize {
    example_main();
    exit(0);
}

// Not used for "panic = abort", but that setting isn't allowed when building tests
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

// These are never called, but the startup code takes their address
#[no_mangle] fn __libc_csu_init() {}
#[no_mangle] fn __libc_csu_fini() {}
#[no_mangle] fn main() {}
