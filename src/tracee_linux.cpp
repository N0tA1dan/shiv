#include "tracee.hpp"
#include <cstdint>
#include <cstring>
#include <cerrno>
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
  pid_t childProc = 0;

  if(m_impl->pid > 0 ) {
    childProc = m_impl->pid;
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
  newRegs.rax = 9;      // SYS_mmap
  newRegs.rdi = 0;      // addr = NULL
  newRegs.rsi = size;    // length
  newRegs.rdx = 3;      // PROT_READ | PROT_WRITE
  newRegs.r10 = 34;     // MAP_PRIVATE | MAP_ANONYMOUS 
  newRegs.r8  = -1;     // fd
  newRegs.r9  = 0;      // offset

  // set new registers
  ptrace(PTRACE_SETREGS, childProc, NULL, &newRegs);

  // execute the single syscall instruction
  ptrace(PTRACE_SINGLESTEP, childProc, NULL, NULL);

  int status;
  waitpid(childProc, &status, 0);

  // store the result, a syscall will return the result in RAX register. Then we put that into allocAddr
  user_regs_struct resultRegs;
  ptrace(PTRACE_GETREGS, childProc, NULL, &resultRegs);
  unsigned long long int allocAddr = resultRegs.rax;

  // restore old context
  ptrace(PTRACE_POKETEXT, childProc, (void*)oldRegs.rip, (void*)oldCode);
  ptrace(PTRACE_SETREGS, childProc, NULL, &oldRegs);


  if ((long)allocAddr < 0 && (long)allocAddr > -4096){
    std::cerr << "mmap failed: errno " << -(long)allocAddr << std::endl;

  }

  m_impl->allocAddr = allocAddr;
  m_impl->allocSize = size;

}

[[nodiscard]] int64_t Tracee::getPid(){
  return m_impl->pid;
}

[[nodiscard]] uint64_t Tracee::getAllocAddr(){
  return m_impl->allocAddr;
}
