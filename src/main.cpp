#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "logger.hpp"

pid_t createProc(const std::string& procName){

  pid_t childProc = fork();

  if(childProc == -1){
    std::cerr << "error: cannot create fork" << std::endl;
    exit(EXIT_FAILURE);
  }

  // within child process
  if(childProc == 0){

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
  createProc(argv[1]);


}

