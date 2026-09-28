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

  uint64_t base = tracee.getAllocAddr();
  uint64_t pid = tracee.getPid();

  std::vector<std::byte> readback;
  for (size_t off = 0; off < payload.size(); off += sizeof(long)) {
    long word = ptrace(PTRACE_PEEKTEXT, pid,
        reinterpret_cast<void*>(base + off), nullptr);
    auto* p = reinterpret_cast<std::byte*>(&word);
    for (size_t i = 0; i < sizeof(long) && readback.size() < payload.size(); ++i)
      readback.push_back(p[i]);
  }

  std::cout << (readback == payload ? "readback MATCHES payload\n"
      : "MISMATCH\n");

  pause();
}

