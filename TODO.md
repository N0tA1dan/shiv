# 14th September 2026


Have target process call mmap() somehow. probably can hack it via ptrace


# 16 September 2026

Pass all arguments to child process.

Also use PATH or figure out how to let shiv know about programs  locally. for example: ./shiv test
instead of: ./shiv ./shiv


## 18 September 2026:

I will use ptrace() PEEKTEXT and POKETEXT to modify the instruction. the idea is that i will save the current registers, RAX, RIP, ETC. using PEEKTEXT to get the current instruction. then i would need to use POKETEXT to write a syscall instruction to that same address somehow. Then fill the registers with the mmap arguments, then i will need to call ptract() PTRACE_SINGLESTEP. then restore the registers after confirming the mmap worked.

I first need to figure out if PEEKTEXT returns the address that the program is currently being executed at

check out https://github.com/akamai/linux-process-injection/blob/main/src/ptrace_primitives.c for more help


<sys/user.h> describes the user_regs_struct which is utilized by ptrace PTRACE_GETREGS. If you look at the struct you can see all the general purpose registers available for said system. Im assuming the struct will differ depending on the architecture as well.

# 20 September 2026

I kinda have to reverse engineer what mmap looks like in assembly because the linux docs dont really give me the exact registers the arguments have to go in. if that makes sense. Im using godbolt.org as a reference with just a program that calls mmap()

heres the exact x86_64 intel assembly for an mmap call of this c code:

```C
int main(void) {
    char *p = mmap(NULL, 100, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

}
```


Assembly:

```
mov     r9d, 0
mov     r8d, -1
mov     ecx, 34
mov     edx, 3
mov     esi, 100
mov     edi, 0
call    "mmap"
mov     QWORD PTR [rbp-8], rax
mov     eax, 0
```


What i need to do now is to peek the word at oldRegs.RIP and save it, then use PTRACE_POKE to overwrite that instruction to the syscall instruction

also i found a source that provides the registers we need to move into accurately for a mmap syscall: https://syscalls.mebeim.net/?table=x86/64/x64/latest

chromium also explains it a bit more: www.chromium.org/chromium-os/developer-library/reference/linux-constants/syscalls/

# 23 September 2026

I completed the basic logic to call mmap within a remote process, next is to clean it up because its very messy. I should also learn how to do a trampoline hook now


# 25 September 2026

I implemented pImpl idiom. So now i can develop both for linux and windows and maybe another platform.

I need to clean up all the code next, pass arguments to target binary, and figure out the next stage of process injection 
