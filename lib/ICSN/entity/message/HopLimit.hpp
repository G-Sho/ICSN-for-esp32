#pragma once

class HopLimit {
private:
  int cnt;

public:
  HopLimit(int cnt) : cnt(cnt) {}
  int getValue() const {
    return cnt;
  };
};
