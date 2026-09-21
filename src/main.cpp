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

void callMap(pid_t childProc, size_t size){

  // todo: save rip, write new instruction, then do syscall

  // save current instructions to be restored later
  user_regs_struct oldRegs;
  ptrace(PTRACE_GETREGS, childProc, NULL, &oldRegs);

  /*
   * We copy oldRegs into newRegs because we are only modifying a few registers.
   * We still need the old ones to keep the program from functioning properly
   */
  user_regs_struct newRegs = oldRegs;
  newRegs.rax = 9;      // SYS_mmap
  newRegs.rdi = 0;      // addr = NULL
  newRegs.rsi = size;    // length
  newRegs.rdx = 3;      // PROT_READ | PROT_WRITE
  newRegs.r10 = 34;     // MAP_PRIVATE | MAP_ANONYMOUS 
  newRegs.r8  = -1;     // fd
  newRegs.r9  = 0;      // offset
                        //
  ptrace(PTRACE_SETREGS, childProc, newRegs, NULL);


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

  // call mmap from here
  callMap(childProc, 1000);


}

