#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include "logger.hpp"

[[nodiscard]] pid_t createProc(const std::string& procName){

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

  }

  int status = 0;
  waitpid(childProc, &status, 0);

  return childProc;

}

[[nodiscard]] unsigned long long int callMap(pid_t childProc, size_t size){

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


  return allocAddr;
}


int main(int argc, char *argv[]) {
  if(argc < 2){
    std::cerr << "error: expected file + optional args. Got 0" << std::endl;
    exit(EXIT_FAILURE);
  }

  Logger logger;

  logger.log(logType::INFO, "Launch sequence starting");
  // create child process
  pid_t childProc = createProc(argv[1]);


  // todo
  //ptrace(PTRACE_CONT, childProc, 0, 0);
  //int status = 0;
  //waitpid(childProc, &status, 0);

  //if (WIFEXITED(status)) {
  //  logger.log(logType::INFO, "child exited, code " + std::to_string(WEXITSTATUS(status)));
  //}
  //

  std::cout << childProc << std::endl;

  // call mmap from here
  auto allocAddr = callMap(childProc, 4098);

  std::cout << "mmap returned addr: " << std::hex << allocAddr << std::endl;

  pause();

}

