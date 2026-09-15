#include "logger.hpp"
#include <iostream>
#include <vector>

void Logger::log(logType type, std::string message) { 

  auto currentTime = time(nullptr);
  logEntry entry = {type, currentTime, message};
  m_logs.push_back(entry); 

}

void Logger::printLogs(){
  for(const auto& log : m_logs){
    std::cout << log.message << std::endl;
  }
}
