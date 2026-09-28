/*
 * target.c -- test victim for shiv.
 *
 * Long-lived so you have time to inject, with one obvious, non-inlined
 * function (`victim`) that shiv can later overwrite with a JMP into the
 * payload. Find its address with:
 *
 *     gcc -O0 -no-pie -o target test/target.c
 *     nm target | grep victim          # static symbol address
 *     ./target                         # runs forever, printing each iteration
 *
 * -no-pie keeps the address fixed (no ASLR slide) which makes early testing
 * far easier; drop it once you handle the load bias.
 */
#include <unistd.h>
#include <stdio.h>

/* The function shiv will hook. noinline so it has a real, stable address. */
__attribute__((noinline))
void victim(int i) {
    printf("victim: iteration %d\n", i);
    fflush(stdout);            /* flush so output is visible before any hook */
}

int main(void) {
    for (int i = 0; ; i++) {
        victim(i);
        sleep(1);
    }
}
