#include "tracee.hpp"
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <vector>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

// impl definition. Will probably be different across different platforms. refer to pimpl idiom
struct Tracee::impl{

  int64_t pid;
  uint64_t allocAddr;
  size_t allocSize;

  [[nodiscard]] user_regs_struct makeSyscall(long long int number, long long int rdi, long long int rsi, long long int rdx, long long int r10, long long int r8, long long int r9){

    pid_t childProc = 0;

    if(pid > 0 ) {
      childProc = pid;
    } else{
      std::cerr << "error: child process id does not exist" << std::endl;
      exit(EXIT_FAILURE);
    }

    // save current instructions to be restored later
    user_regs_struct oldRegs;
    ptrace(PTRACE_GETREGS, childProc, NULL, &oldRegs);

    // get current instruction
    long oldCode = ptrace(PTRACE_PEEKTEXT, childProc, oldRegs.rip, NULL);

    long patched = (oldCode & ~0xFFFFL) | 0x050F;
    ptrace(PTRACE_POKETEXT, childProc, (void*)oldRegs.rip, (void*)patched);

    /*
     * We copy oldRegs into newRegs because we are only modifying a few registers.
     * We still need the old ones to keep the program from functioning properly
     * We set the addr to null so the kernel will decide where to make the allocation
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
    ptrace(PTRACE_SETREGS, childProc, NULL, &newRegs);

    // execute the single syscall instruction
    ptrace(PTRACE_SINGLESTEP, childProc, NULL, NULL);

    int status;
    waitpid(childProc, &status, 0);

    // store the result, a syscall will return the result in RAX register. Then we put that into allocAddr
    user_regs_struct resultRegs;
    ptrace(PTRACE_GETREGS, childProc, NULL, &resultRegs);

    // restore old context
    ptrace(PTRACE_POKETEXT, childProc, (void*)oldRegs.rip, (void*)oldCode);
    ptrace(PTRACE_SETREGS, childProc, NULL, &oldRegs);

    return resultRegs;

  }

};

Tracee::Tracee() {

  m_impl = std::make_unique<impl>();

  m_impl->allocAddr = 0;

  m_impl->pid = 0;
}

Tracee::~Tracee() = default;

void Tracee::initProc(const std::string& procName){

  pid_t childProc = fork();

  if(childProc == -1){
    std::cerr << "error: cannot create fork" << std::endl;
    exit(EXIT_FAILURE);
  }

  // within child process
  if(childProc == 0){

    // stop execution and allows for tracing
    ptrace(PTRACE_TRACEME, NULL, NULL, NULL);

    // load target process
    char *args[] = {const_cast<char*>(procName.c_str()), NULL};
    execvp(procName.c_str(), args);

    // execvp only returns on failure; reaching here means the exec failed.
    std::cerr << "error: cannot exec '" << procName << "': " << std::strerror(errno) << std::endl;
    _exit(EXIT_FAILURE);

  }

  int status = 0;
  if(waitpid(childProc, &status, 0) == -1){
    std::cerr << "error: waitpid failed on child process" << std::endl;
    m_impl->pid = -1;
    return;
  }

  /*
   * A successful PTRACE_TRACEME + execvp leaves the child trace-stopped on the
   * exec, so waitpid must report a stopped child. If it didn't stop, the exec
   * failed (child _exit'd) or the child died some other way, so there is no
   * valid tracee to record.
   */
  if(!WIFSTOPPED(status)){
    std::cerr << "error: child did not stop for tracing (exec likely failed)" << std::endl;
    m_impl->pid = -1;
    return;
  }

  m_impl->pid = childProc;

}

void Tracee::createAlloc(size_t size){

  user_regs_struct result = m_impl->makeSyscall(
      SYS_mmap,                        // number
      0,                               // addr  = NULL (kernel chooses)
      static_cast<long long>(size),    // length
      PROT_READ | PROT_WRITE,          // prot
      MAP_PRIVATE | MAP_ANONYMOUS,     // flags
      -1,                              // fd
      0);

  m_impl->allocAddr = result.rax;
  m_impl->allocSize = size;

}

void Tracee::writePayload(const std::vector<std::byte>& payload){

  // get page size
  long pageSize = sysconf(_SC_PAGE_SIZE);

  long totalSize = 0;

  int remainder = m_impl->allocSize % pageSize;

  if (remainder == 0)
    totalSize = m_impl->allocSize;

  // calculate total pages allocated
  totalSize = m_impl->allocSize + pageSize - remainder;


  // change allocated pages to R + E
  user_regs_struct result = m_impl->makeSyscall(
      0xa, // MPROTECT Syscall number
      m_impl->allocAddr,              // page base address
      static_cast<size_t>(totalSize), // total page size
      PROT_READ | PROT_EXEC,          // prot
      0,     // flags
      0,
      0);

  if(result.rax == -1){
    std::cerr << "error: mprotect failed to set read + exec for page" << std::endl;
    exit(EXIT_FAILURE);
  }

  /*
   * Write bytes word by word via ptrace
   */
  constexpr size_t kWord = sizeof(long);

  // starting address
  uint64_t base = m_impl->allocAddr;
  int64_t pid = m_impl->pid;

  for (size_t offset = 0; offset < payload.size(); offset += kWord) {
    size_t chunk = std::min(kWord, payload.size() - offset);
    void* dst = reinterpret_cast<void*>(base + offset);

    long word = 0;
    if (chunk < kWord) {                       // partial tail: preserve neighbors
      errno = 0;
      word = ptrace(PTRACE_PEEKTEXT, pid, dst, nullptr);
      if (word == -1 && errno) { /* handle error */ }
    }
    std::memcpy(&word, &payload[offset], chunk);

    if (ptrace(PTRACE_POKETEXT, pid, dst, reinterpret_cast<void*>(word)) == -1) {
      /* handle error */
    }
  }

}

[[nodiscard]] int64_t Tracee::getPid(){
  return m_impl->pid;
}

[[nodiscard]] uint64_t Tracee::getAllocAddr(){
  return m_impl->allocAddr;
}
