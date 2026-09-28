#include <iostream>
#include <unistd.h>

int main(){
  long p = sysconf(_SC_PAGESIZE);
  std::cout << p << std::endl;
}
