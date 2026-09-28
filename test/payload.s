/*
 * payload.s -- freestanding smoke-test shellcode for shiv (x86-64 Linux).
 *
 * No libc, no globals, no .rodata. The string is materialized as an
 * immediate and pushed onto the stack, so it survives
 * `objcopy -j .text` (only .text is extracted). Entry is at offset 0.
 *
 * Behavior: write(1, "HOOKED\n", 7), then int3 to trap back to the tracer
 * so shiv's waitpid() confirms the payload actually ran.
 *
 * Build (matches TODO pipeline):
 *     gcc -c -ffreestanding -fno-stack-protector \
 *         -fno-asynchronous-unwind-tables -fcf-protection=none \
 *         test/payload.s -o payload.o
 *     objcopy -O binary -j .text payload.o payload.bin
 *     ndisasm -b 64 payload.bin      # verify: clean, self-contained instrs
 *     xxd -i payload.bin             # C array, or read the file at runtime
 */
    .intel_syntax noprefix
    .text
    .globl _start
_start:
    /* "HOOKED\n\0" as a little-endian 64-bit immediate:
       H=48 O=4F O=4F K=4B E=45 D=44 \n=0A, high byte 00 (NUL). */
    mov     rax, 0x000A44454B4F4F48
    push    rax                     /* [rsp] -> "HOOKED\n\0" */

    /* write(1, rsp, 7) */
    mov     rax, 1                  /* SYS_write */
    mov     rdi, 1                  /* fd = stdout */
    mov     rsi, rsp               /* buf = string on the stack */
    mov     rdx, 7                  /* count */
    syscall

    add     rsp, 8                  /* pop the pushed string */

    int3                            /* trap back to shiv (smoke-test marker) */
