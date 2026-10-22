#pragma once

#include <iostream>
#include <vector>
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

  void readPayloadFromFile(std::string fileName);

  void writePayload(const std::vector<std::byte>& payload);

  void hookFunction(int64_t functionAddr);

  void waitForMain(int64_t mainAddr);

  void detach();

  [[nodiscard]] int64_t getPid();

  [[nodiscard]] uint64_t getLibraryAddr(const std::string& libraryName);

  [[nodiscard]] uint64_t getAllocAddr();

  [[nodiscard]] uint64_t getBaseAddr();


};
