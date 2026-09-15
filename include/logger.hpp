#pragma once
#include <ctime>
#include <vector>
#include <string>

enum class logType { DEBUG, INFO, WARNING, ERROR };

struct logEntry {
  logType type;
  std::time_t timeStamp;
  std::string message;
};

class Logger {
private:
  std::vector<logEntry> m_logs;

public:
  void log(logType type, std::string message);

  void printLogs();
};
