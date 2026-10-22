#include "tracee.hpp"
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <vector>
#include <array>
#include <fstream>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

// impl definition. Will probably be different across different platforms.
struct Tracee::impl{

  int64_t pid;

  bool isPie;

  // for mmap
  uint64_t allocAddr;
  size_t allocSize;

  // programs base address read from /proc/<pid>/maps
  uint64_t baseAddr;

  void parseElf(const std::string& progName){

    //read ELF e_ident + e_type (handles both endiannesses)
    std::ifstream elf(progName, std::ios::binary);
    if (!elf) {
      throw std::runtime_error("error: cannot open ELF file");
    }

    std::array<unsigned char, 18> hdr{};  // e_ident (16) + e_type (2)
    elf.read(reinterpret_cast<char*>(hdr.data()), hdr.size());
    if (!elf) {
      throw std::runtime_error("error: short read on ELF header");
    }

    if (hdr[0] != 0x7F || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F') {
      throw std::runtime_error("error: not an ELF file");
    }

    const bool littleEndian = (hdr[5] == 1);  // EI_DATA: 1=LSB, 2=MSB

    uint16_t eType = 0;
    if (littleEndian) {
      eType = static_cast<uint16_t>(hdr[16] | (hdr[17] << 8));
    } else {
      eType = static_cast<uint16_t>(hdr[17] | (hdr[16] << 8));
    }

    constexpr uint16_t ET_EXEC = 2;
    constexpr uint16_t ET_DYN  = 3;

    // determines if executable is Pie or non-pie. Checking if we need to account for ASLR to calculate base address
    // we read the ELF header. Refer to wikipedia to see the header standard
    if (eType == ET_EXEC) {
      isPie = false;
      baseAddr = 0;
    } 
    else if (eType == ET_DYN) {
      isPie = true;

      // first line of /proc/<pid>/maps starts with "<base>-<end> ..."
      std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
      std::string line;

      if (!std::getline(maps, line)) {
        throw std::runtime_error("error: cannot read /proc/<pid>/maps");
      }

      baseAddr = std::stoull(line.substr(0, line.find('-')), nullptr, 16);

    } else {
      throw std::runtime_error("error: unsupported ELF e_type");
    }


  }

  [[nodiscard]] user_regs_struct makeSyscall(uint64_t number, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10, uint64_t r8, uint64_t r9){

    pid_t childProc = 0;

    if(pid > 0 ) {
      childProc = pid;
    } else{
      throw std::runtime_error("error: process not initialized or terminated");
    }

    // return value of each ptrace call below, checked right after the call is made
    long ret;

    // save current instructions to be restored later
    user_regs_struct oldRegs;
    ret = ptrace(PTRACE_GETREGS, childProc, NULL, &oldRegs);
    if (ret == -1) {
      throw std::runtime_error("error: PTRACE_GETREGS failed");
    }

    // get current instruction
    errno = 0;
    long oldCode = ptrace(PTRACE_PEEKTEXT, childProc, oldRegs.rip, NULL);
    if (oldCode == -1 && errno) {
      throw std::runtime_error("error: PTRACE_PEEKTEXT failed");
    }

    // syscall instruction
    long syscallInstruction = (oldCode & ~0xFFFFL) | 0x050F;
    ret = ptrace(PTRACE_POKETEXT, childProc, (void*)oldRegs.rip, (void*)syscallInstruction);
    if (ret == -1) {
      throw std::runtime_error("error: PTRACE_POKETEXT failed while writing syscall instruction");
    }

    /*
     * We copy oldRegs into newRegs because we are only modifying a few registers.
     */
    user_regs_struct newRegs = oldRegs;
    newRegs.rax = number;      // SYSCALL number 
    newRegs.rdi = rdi;
    newRegs.rsi = rsi;
    newRegs.rdx = rdx;
    newRegs.r10 = r10;
    newRegs.r8  = r8;
    newRegs.r9  = r9;

    // set new registers
    ret = ptrace(PTRACE_SETREGS, childProc, NULL, &newRegs);
    if (ret == -1) {
      throw std::runtime_error("error: PTRACE_SETREGS failed");
    }

    // execute the single syscall instruction
    ret = ptrace(PTRACE_SINGLESTEP, childProc, NULL, NULL);
    if (ret == -1) {
      throw std::runtime_error("error: PTRACE_SINGLESTEP failed");
    }

    int status;
    long waitRet = waitpid(childProc, &status, 0);
    if (waitRet == -1) {
      throw std::runtime_error("error: waitpid failed while executing syscall");
    }

    // store the result, a syscall will return the result in RAX register. Then we put that into allocAddr
    user_regs_struct resultRegs;
    ret = ptrace(PTRACE_GETREGS, childProc, NULL, &resultRegs);
    if (ret == -1) {
      throw std::runtime_error("error: PTRACE_GETREGS failed while reading syscall result");
    }

    // restore old context
    ret = ptrace(PTRACE_POKETEXT, childProc, (void*)oldRegs.rip, (void*)oldCode);
    if (ret == -1) {
      throw std::runtime_error("error: PTRACE_POKETEXT failed while restoring original instruction");
    }
    ret = ptrace(PTRACE_SETREGS, childProc, NULL, &oldRegs);
    if (ret == -1) {
      throw std::runtime_error("error: PTRACE_SETREGS failed while restoring original registers");
    }

    return resultRegs;

  }

};

Tracee::Tracee() {

  m_impl = std::make_unique<impl>();

  m_impl->allocAddr = 0;

  m_impl->allocSize = 0;

  m_impl->pid = 0;

}

Tracee::~Tracee() {
  // best-effort cleanup: don't throw out of a destructor, just try to detach
  if (m_impl->pid > 0) {
    ptrace(PTRACE_DETACH, m_impl->pid, NULL, NULL);
  }
}

void Tracee::initProc(const std::string& progName){

  pid_t childProc = fork();

  if(childProc == -1){
    throw std::runtime_error("error: cannot create fork");
  }

  // within child process
  if(childProc == 0){

    // stop execution and allows for tracing
    ptrace(PTRACE_TRACEME, NULL, NULL, NULL);

    // load target process
    char *args[] = {const_cast<char*>(progName.c_str()), NULL};
    execvp(progName.c_str(), args);

    // execvp only returns on failure; reaching here means the exec failed.
    std::cerr << "error: cannot exec '" << progName << "': " << std::strerror(errno) << std::endl;
    _exit(EXIT_FAILURE);

  }

  int status = 0;
  if(waitpid(childProc, &status, 0) == -1){
    throw std::runtime_error("error: waitpid failed on child process");
  }

  /*
   * A successful PTRACE_TRACEME + execvp leaves the child trace-stopped on the
   * exec, so waitpid must report a stopped child. If it didn't stop, the exec
   * failed (child _exit'd) or the child died some other way, so there is no
   * valid tracee to record.
   */
  if(!WIFSTOPPED(status)){
    throw std::runtime_error("error: child did not stop for tracing (exec likely failed)");
  }

  // set pid
  m_impl->pid = childProc;

  // parse elf header for PIE/NON-PIE binaries
  m_impl->parseElf(progName);

}

void Tracee::waitForMain(int64_t mainAddr) {
  uint64_t addr = m_impl->baseAddr + mainAddr;

  // read the original byte and replace with int3
  long orig = ptrace(PTRACE_PEEKTEXT, m_impl->pid, addr, NULL);
  long trap = (orig & ~0xFF) | 0xCC;
  ptrace(PTRACE_POKETEXT, m_impl->pid, addr, trap);

  // run at full speed until breakpoint
  ptrace(PTRACE_CONT, m_impl->pid, NULL, NULL);
  int status = 0;
  waitpid(m_impl->pid, &status, 0);

  // restore original instruction and rewind rip past the int3
  ptrace(PTRACE_POKETEXT, m_impl->pid, addr, orig);
  user_regs_struct regs;
  ptrace(PTRACE_GETREGS, m_impl->pid, NULL, &regs);
  regs.rip = addr;
  ptrace(PTRACE_SETREGS, m_impl->pid, NULL, &regs);
}

void Tracee::detach(){
  long ret = ptrace(PTRACE_DETACH, m_impl->pid, NULL, NULL);
  if (ret == -1) {
    throw std::runtime_error("error: PTRACE_DETACH failed");
  }
}

void Tracee::createAlloc(size_t size){

  user_regs_struct result = m_impl->makeSyscall(
      SYS_mmap,
      0,                               // addr  = NULL (kernel chooses)
      static_cast<long long>(size),    // length
      PROT_READ | PROT_WRITE,          // prot
      MAP_PRIVATE | MAP_ANONYMOUS,     // flags
      -1,                              // fd
      0);

  if (result.rax == static_cast<uint64_t>(-1)) {
    throw std::runtime_error("error: mmap failed to allocate memory in target process");
  }

  m_impl->allocAddr = result.rax;
  m_impl->allocSize = size;

}

void Tracee::writePayload(const std::vector<std::byte>& payload){

  // get page size
  long pageSize = sysconf(_SC_PAGE_SIZE);
  long totalSize = 0;
  int remainder = m_impl->allocSize % pageSize;

  // calculate total pages allocated by mmap
  if (remainder == 0){
    totalSize = m_impl->allocSize;
  } 
  else{
    totalSize = m_impl->allocSize + pageSize - remainder;
  }

  constexpr size_t kWord = sizeof(long);
  // starting address
  uint64_t base = m_impl->allocAddr;
  int64_t pid = m_impl->pid;

  // write payload word by word into our base address from mmap
  for (size_t offset = 0; offset < payload.size(); offset += kWord) {
    size_t chunk = std::min(kWord, payload.size() - offset);
    void* dst = reinterpret_cast<void*>(base + offset);

    long word = 0;
    if (chunk < kWord) {                       // partial tail: preserve neighbors
      errno = 0;
      word = ptrace(PTRACE_PEEKTEXT, pid, dst, nullptr);
      if (word == -1 && errno) {
        throw std::runtime_error("error: reading word from process");
      }
    }
    std::memcpy(&word, &payload[offset], chunk);

    if (ptrace(PTRACE_POKETEXT, pid, dst, reinterpret_cast<void*>(word)) == -1) {
      throw std::runtime_error("error: writing word into process failed");
    }
  }

  // change allocated pages to R + E
  user_regs_struct result = m_impl->makeSyscall(
      SYS_mprotect,
      m_impl->allocAddr,
      static_cast<size_t>(totalSize),
      PROT_READ | PROT_EXEC,
      0,
      0,
      0);

  if(static_cast<int>(result.rax) == -1){
    throw std::runtime_error("error: mprotect failed to set read + exec for allocated memory");
  }

}

void Tracee::hookFunction(int64_t functionAddr){

  // get real function address offset from ASLR address
  functionAddr = m_impl->baseAddr + functionAddr;

  // 12-byte absolute jump: movabs rax, allocAddr ; jmp rax
  // 48 b8 <8-byte abs addr LE>  ff e0
  uint8_t patch[12] = { 0x48, 0xb8, 0,0,0,0,0,0,0,0, 0xff, 0xe0 };
  std::memcpy(&patch[2], &m_impl->allocAddr, 8);

  // return value of each ptrace call below, checked right after the call is made
  long ret;

  // first word: bytes 0..7 of patch (full word, no merge needed)
  uint64_t word1;
  std::memcpy(&word1, &patch[0], 8);
  ret = ptrace(PTRACE_POKETEXT, m_impl->pid, functionAddr, word1);
  if (ret == -1) {
    throw std::runtime_error("error: PTRACE_POKETEXT failed while writing hook jump");
  }

  // second word: bytes 8..11 of patch + preserve the 4 bytes after the patch
  errno = 0;
  uint64_t word2 = ptrace(PTRACE_PEEKTEXT, m_impl->pid, functionAddr + 8, NULL);
  if (word2 == static_cast<uint64_t>(-1) && errno) {
    throw std::runtime_error("error: PTRACE_PEEKTEXT failed while reading bytes after hook");
  }
  std::memcpy(&word2, &patch[8], 4);
  ret = ptrace(PTRACE_POKETEXT, m_impl->pid, functionAddr + 8, word2);
  if (ret == -1) {
    throw std::runtime_error("error: PTRACE_POKETEXT failed while writing hook jump tail");
  }

}

[[nodiscard]] uint64_t Tracee::getLibraryAddr(const std::string& libraryName){

  std::string line;
  std::ifstream maps("/proc/" + std::to_string(m_impl->pid) + "/maps");

  if(!maps){
    throw std::runtime_error("error: getLibraryAddr could not open maps");
  }

  while(std::getline(maps, line)){

    if(line.find(libraryName) != std::string::npos){
      return std::stoull(line.substr(0, line.find('-')), nullptr, 16);
    }

  }

  throw std::runtime_error("error: cannot find " + libraryName + " address. is it included in the program?");

}

[[nodiscard]] int64_t Tracee::getPid(){
  return m_impl->pid;
}

[[nodiscard]] uint64_t Tracee::getAllocAddr(){
  return m_impl->allocAddr;
}

[[nodiscard]] uint64_t Tracee::getBaseAddr(){
  return m_impl->baseAddr;
}
