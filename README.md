Tiny Seccomp
-------------

Sometimes you need a syscall filter without an entire dynamic library. Or std. Or an allocator. Or std. Whatever! Just throw some instructions in a buffer, we can do it.

It's just a basic seccomp thing that doesn't use libseccomp. Only tested/works on `x86_64` so far.

Right now it requires nightly rust, because the `sc` syscall crate uses inline assembly.

The included example doesn't use the Rust standard library, the allocator, or any libc. Currently it compiles in release mode to 36 kB.
