# 14th September 2026


Have target process call mmap() somehow. probably can hack it via ptrace


# 16 September 2026

Pass all arguments to child process.

Also use PATH or figure out how to let shiv know about programs  locally. for example: ./shiv test
instead of: ./shiv ./shiv


## 19 September 2026:

I will use ptrace() PEEKTEXT and POKETEXT to modify the instruction. the idea is that i will save the current registers, RAX, RIP, ETC. using PEEKTEXT to get the current instruction. then i would need to use POKETEXT to write a syscall instruction to that same address somehow. Then fill the registers with the mmap arguments, then i will need to call ptract() PTRACE_SINGLESTEP. then restore the registers after confirming the mmap worked.

I first need to figure out if PEEKTEXT returns the address that the program is currently being executed at

check out https://github.com/akamai/linux-process-injection/blob/main/src/ptrace_primitives.c for more help
