Tiny Seccomp
-------------

Sometimes you need a syscall filter without an entire dynamic library. Or any dynamic libraries. Or an allocator. Or std. Whatever! Just throw some instructions in a buffer, we can do it.

It's just a basic seccomp thing that doesn't use libseccomp. Only tested on `x86_64` so far.

