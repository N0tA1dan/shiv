#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include "tracee.hpp"


int main(int argc, char *argv[]) {

  if(argc < 2){
    std::cerr << "error: expected file + optional args. Got 0" << std::endl;
    exit(EXIT_FAILURE);
  }

  Tracee tracee;

  // start process
  tracee.initProc(argv[1]);
  std::cout << "Target Process ID: " << tracee.getPid() << std::endl;

  // mmap underneath. returns multiple of pages, not exact bytes like malloc()
  tracee.createAlloc(100);
  std::cout << "MMAP alloc address: " << std::hex << tracee.getAllocAddr() << std::endl;

  std::cout << "program base addr: " << std::hex << tracee.getBaseAddr() << std::endl;

  uint8_t bytes[] = {
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,   // mov rax, 1          (sys_write)
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,   // mov rdi, 1          (stdout)
    0x48, 0x8d, 0x35, 0x0a, 0x00, 0x00, 0x00,   // lea rsi, [rip+10]   -> string below
    0x48, 0xc7, 0xc2, 0x0f, 0x00, 0x00, 0x00,   // mov rdx, 15         (length)
    0x0f, 0x05,                                 // syscall
    0xc3,                                       // ret
    'h','o','o','k','e','d',' ','m','e','o','w',' ',':','3','\n'
  };

  std::vector<std::byte> payload(
      reinterpret_cast<const std::byte*>(bytes),
      reinterpret_cast<const std::byte*>(std::end(bytes)));

  // writes payload in bytes
  tracee.writePayload(payload);

  // trampoline hook function at given address
  tracee.hookFunction(0x1139);

  pause();
}

