# Notes

## Linux Documentation

PTRACE DOCS: https://www.man7.org/linux/man-pages/man2/ptrace.2.html

MMAP DOCS: https://linux.die.net/man/2/mmap

SYSCONF (used for getting page size): https://www.man7.org/linux/man-pages/man3/sysconf.3.html

https://linux.die.net/man/2/mprotect

ASLR: https://linuxvox.com/blog/aslr-linux/


## 1 October 2026


I found a really good guide/series that goes into depth of linux process injection. They use a lot of the same logic but they look for code caves i believe, not mmap forcefully to get an executable piece of memory

source: https://mathscantor.github.io/posts/linux-processing-injection-guide/part-1-overview/

## 6 October 2026

Ghidra and objdump and gdb seem to get the correct static address of instructions in a binary. so im **assuming** people could insert the address from ghidra or any other debugger/disassembler into shiv and itll hook normally

For the hook payload, if you have the same parameters for your target function, you can access the values passed to the target function when its called. they have to be exact with the same types and everything
