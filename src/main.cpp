#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
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
  ptrace(PTRACE_CONT, childProc, 0, 0);
  int status = 0;
  waitpid(childProc, &status, 0);

  if (WIFEXITED(status)) {
    logger.log(logType::INFO, "child exited, code " + std::to_string(WEXITSTATUS(status)));
  }

  

}

