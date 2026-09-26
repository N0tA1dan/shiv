#pragma once

#include <iostream>
#include <string>
#include <memory>
#include <cstdint>

class Tracee{
private:
  struct impl;
  std::unique_ptr<impl> m_impl;

public:
  
  Tracee();
  ~Tracee();

  void initProc(const std::string& procName);

  void createAlloc(size_t size);

  [[nodiscard]] int64_t getPid();

  [[nodiscard]] uint64_t getAllocAddr();


};
