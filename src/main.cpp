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

  const unsigned char bytes[] = {
    0x48,0xb8,0x48,0x4f,0x4f,0x4b,0x45,0x44,0x0a,0x00,0x50,0x48,
    0xc7,0xc0,0x01,0x00,0x00,0x00,0x48,0xc7,0xc7,0x01,0x00,0x00,
    0x00,0x48,0x89,0xe6,0x48,0xc7,0xc2,0x07,0x00,0x00,0x00,0x0f,
    0x05,0x48,0x83,0xc4,0x08,0xcc,
  };
  std::vector<std::byte> payload(
      reinterpret_cast<const std::byte*>(bytes),
      reinterpret_cast<const std::byte*>(std::end(bytes)));

  // writes payload in bytes
  tracee.writePayload(payload);

  std::cout << "program base addr: " << std::hex << tracee.getBaseAddr() << std::endl;

  //int64_t instruction = 0;

  //int64_t baseAddr = 0;
  //int64_t functionAddr = 0;

  //std::cout << "enter base addr: ";
  //std::cin >> std::hex >> baseAddr;

  //std::cout << "enter function addr: ";
  //std::cin >> std::hex >> functionAddr;

  //
  //instruction = ptrace(PTRACE_PEEKTEXT, pid, baseAddr+functionAddr, NULL);

  //std::cout << std::hex << instruction << std::endl;
  

  pause();
}

