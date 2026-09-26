#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include "logger.hpp"
#include "tracee.hpp"


int main(int argc, char *argv[]) {
  if(argc < 2){
    std::cerr << "error: expected file + optional args. Got 0" << std::endl;
    exit(EXIT_FAILURE);
  }

  Logger logger;

  logger.log(logType::INFO, "Launch sequence starting");
  
  // create child process
  //pid_t childProc = createProc(argv[1]);
  //std::cout << childProc << std::endl;

  // call mmap from here
  //auto allocAddr = callMap(childProc, 4098);

  //std::cout << "mmap returned addr: " << std::hex << allocAddr << std::endl;

  //pause();


  Tracee tracee;

  tracee.initProc(argv[1]);
  std::cout << "Target Process ID: " << tracee.getPid() << std::endl;

  tracee.createAlloc(100);
  std::cout << "MMAP alloc address: " << std::hex << tracee.getAllocAddr() << std::endl;

  pause();

}

