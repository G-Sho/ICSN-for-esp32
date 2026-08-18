#pragma once

#include "BuildCapacity.hpp"
#include <cstddef>
#include <cstdint>

// セキュリティ関連定数
constexpr size_t ESP_NOW_PMK_LEN = 16;
constexpr size_t ESP_NOW_LMK_LEN = 16;
constexpr size_t ICSN_HMAC_KEY_LEN = 16;

/// @brief ピア固有キー設定エントリ
struct PeerKeyConfig {
  uint8_t mac[6];               ///< ピアのMACアドレス
  uint8_t key[ESP_NOW_LMK_LEN]; ///< このピア向けの16バイト鍵
  bool valid;                   ///< エントリが有効かどうか
};

/// @brief ピア固有鍵の最大登録数
constexpr size_t MAX_PEER_KEY_ENTRIES = 20;

/// @brief FIB初期エントリ（起動時にFIBへ投入するルーティング設定）
struct FibInitEntry {
  char contentName[64]; ///< コンテンツ名プレフィックス（例: "/iot/buildingA/room101"）
  /// 次ホップMACアドレス（小文字コロン区切り、例: "cc:7b:5c:9a:f3:ac"）
  char nextHopMac[18];
  /// エントリが有効かどうか
  bool valid;
};

/// @brief FIB初期エントリの最大数
constexpr size_t MAX_FIB_INIT_ENTRIES = 10;

struct SystemConfig {
  int maxVirtualDepth = 5;
  int defaultInterestHopLimit = 10;

  // ESP-NOW CCMP 設定
  bool espNowEncryptionEnabled = false;
  uint8_t espNowPmk[ESP_NOW_PMK_LEN] = {0};
  bool espNowPmkConfigured = false;
  uint8_t espNowDefaultLmk[ESP_NOW_LMK_LEN] = {0};
  bool espNowDefaultLmkConfigured = false;
  PeerKeyConfig espNowPeerLmkEntries[MAX_PEER_KEY_ENTRIES];
  size_t espNowPeerLmkCount = 0;

  // ICSN HMAC 設定
  bool hmacAuthenticationEnabled = false;
  uint8_t hmacDefaultKey[ICSN_HMAC_KEY_LEN] = {0};
  bool hmacDefaultKeyConfigured = false;
  PeerKeyConfig hmacPeerKeyEntries[MAX_PEER_KEY_ENTRIES];
  size_t hmacPeerKeyCount = 0;

  // FIB初期エントリ（テスト用ブランチで多段経路を事前設定するために使用）
  FibInitEntry fibInitEntries[MAX_FIB_INIT_ENTRIES];
  size_t fibInitCount = 0;
};

extern SystemConfig systemConfig;

bool loadSystemConfig(const char* path = "/config.json");
