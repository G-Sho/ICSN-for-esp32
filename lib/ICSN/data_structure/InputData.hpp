#pragma once

#include "message/SignalCode.hpp"
#include <cstdint>
#include <set>
#include <string>

struct InputData {
  std::string senderId;
  std::set<std::string> destId;
  std::string signalCode;
  int hopLimit;
  std::string contentName;
  std::string content;

  InputData(const std::string& senderId, const std::set<std::string>& destId,
            const std::string& signalCode, int hopLimit, const std::string& contentName,
            const std::string& content)
      : senderId(senderId), destId(destId), signalCode(signalCode), hopLimit(hopLimit),
        contentName(contentName), content(content) {}
};
