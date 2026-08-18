#include "Config.hpp"
#include "BuildProfile.hpp"
#include <ArduinoJson.h>
#include <LittleFS.h>

SystemConfig systemConfig;

/// @brief 16進数文字列をバイト配列に変換する
/// @param hexStr 32文字の16進数文字列（16バイト分）
/// @param out 出力先バッファ（16バイト）
/// @return 成功時true
static bool hexStringToBytes(const char* hexStr, uint8_t* out, size_t outLen) {
  if (hexStr == nullptr || out == nullptr)
    return false;
  size_t strLen = strlen(hexStr);
  if (strLen != outLen * 2)
    return false;

  for (size_t i = 0; i < outLen; i++) {
    char byteStr[3] = {hexStr[i * 2], hexStr[i * 2 + 1], '\0'};
    char* endPtr = nullptr;
    unsigned long val = strtoul(byteStr, &endPtr, 16);
    if (endPtr != byteStr + 2 || val > 255)
      return false;
    out[i] = static_cast<uint8_t>(val);
  }
  return true;
}

/// @brief コロン区切りMAC文字列をバイト配列に変換する（例: "CC:7B:5C:9A:F3:C4"）
/// @param macStr MACアドレス文字列
/// @param out 出力先バッファ（6バイト）
/// @return 成功時true
static bool macStringToBytes(const char* macStr, uint8_t out[6]) {
  if (macStr == nullptr || out == nullptr)
    return false;
  unsigned int b[6];
  if (sscanf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) !=
      6)
    return false;
  for (int i = 0; i < 6; i++) {
    out[i] = static_cast<uint8_t>(b[i]);
  }
  return true;
}

static void resetSecurityConfig() {
  systemConfig.espNowEncryptionEnabled = false;
  systemConfig.espNowPmkConfigured = false;
  memset(systemConfig.espNowPmk, 0, sizeof(systemConfig.espNowPmk));

  systemConfig.espNowDefaultLmkConfigured = false;
  memset(systemConfig.espNowDefaultLmk, 0, sizeof(systemConfig.espNowDefaultLmk));
  systemConfig.espNowPeerLmkCount = 0;
  memset(systemConfig.espNowPeerLmkEntries, 0, sizeof(systemConfig.espNowPeerLmkEntries));

  systemConfig.hmacAuthenticationEnabled = false;
  systemConfig.hmacDefaultKeyConfigured = false;
  memset(systemConfig.hmacDefaultKey, 0, sizeof(systemConfig.hmacDefaultKey));
  systemConfig.hmacPeerKeyCount = 0;
  memset(systemConfig.hmacPeerKeyEntries, 0, sizeof(systemConfig.hmacPeerKeyEntries));
}

static size_t loadPeerKeys(JsonVariantConst peersNode, const char* keyName,
                           PeerKeyConfig* outEntries, size_t maxEntries) {
  if (!peersNode.is<JsonArrayConst>() || outEntries == nullptr || keyName == nullptr) {
    return 0;
  }

  size_t count = 0;
  JsonArrayConst peers = peersNode.as<JsonArrayConst>();
  for (JsonObjectConst peer : peers) {
    if (count >= maxEntries) {
      break;
    }

    const char* macStr = peer["mac"] | peer["peer_mac"] | "";
    const char* keyStr = peer[keyName] | peer["lmk"] | peer["hmac_key"] | "";

    PeerKeyConfig& entry = outEntries[count];
    if (macStringToBytes(macStr, entry.mac) &&
        hexStringToBytes(keyStr, entry.key, ESP_NOW_LMK_LEN)) {
      entry.valid = true;
      count++;
    }
  }

  return count;
}

static void loadLegacySecurityConfig(const JsonDocument& doc) {
  const char* pmkStr = doc["PMK"] | "";
  const char* lmkStr = doc["LMK"] | "";

  const bool pmkValid = hexStringToBytes(pmkStr, systemConfig.espNowPmk, ESP_NOW_PMK_LEN);
  const bool lmkValid = hexStringToBytes(lmkStr, systemConfig.espNowDefaultLmk, ESP_NOW_LMK_LEN);

  systemConfig.espNowPmkConfigured = pmkValid;
  systemConfig.espNowDefaultLmkConfigured = lmkValid;
  systemConfig.espNowEncryptionEnabled = pmkValid;

  if (lmkValid) {
    memcpy(systemConfig.hmacDefaultKey, systemConfig.espNowDefaultLmk, ICSN_HMAC_KEY_LEN);
    systemConfig.hmacDefaultKeyConfigured = true;
    systemConfig.hmacAuthenticationEnabled = true;
  }

  systemConfig.espNowPeerLmkCount =
      loadPeerKeys(doc["peers"], "lmk", systemConfig.espNowPeerLmkEntries, MAX_PEER_KEY_ENTRIES);

  systemConfig.hmacPeerKeyCount =
      loadPeerKeys(doc["peers"], "lmk", systemConfig.hmacPeerKeyEntries, MAX_PEER_KEY_ENTRIES);

  if (pmkValid || lmkValid || systemConfig.espNowPeerLmkCount > 0) {
    LOG_WARN("[WARN][SEC] config_deprecated reason=legacy_security_fields");
  }
}

static void loadSeparatedSecurityConfig(const JsonDocument& doc) {
  JsonObjectConst espNowSecurity = doc["esp_now_security"].as<JsonObjectConst>();
  JsonObjectConst icsnSecurity = doc["icsn_security"].as<JsonObjectConst>();

  const bool espNowEnabledFlag = espNowSecurity["enabled"] | false;
  const char* pmkStr = espNowSecurity["pmk"] | "";
  const char* defaultLmkStr = espNowSecurity["default_lmk"] | "";

  systemConfig.espNowPmkConfigured =
      hexStringToBytes(pmkStr, systemConfig.espNowPmk, ESP_NOW_PMK_LEN);
  systemConfig.espNowDefaultLmkConfigured =
      hexStringToBytes(defaultLmkStr, systemConfig.espNowDefaultLmk, ESP_NOW_LMK_LEN);
  systemConfig.espNowPeerLmkCount = loadPeerKeys(
      espNowSecurity["peers"], "lmk", systemConfig.espNowPeerLmkEntries, MAX_PEER_KEY_ENTRIES);

  systemConfig.espNowEncryptionEnabled = espNowEnabledFlag && systemConfig.espNowPmkConfigured;
  if (espNowEnabledFlag && !systemConfig.espNowPmkConfigured) {
    LOG_WARN("[WARN][SEC] config_invalid reason=pmk_missing_or_invalid");
  }

  const bool hmacEnabledFlag = icsnSecurity["hmac_enabled"] | false;
  const char* defaultHmacKeyStr = icsnSecurity["default_hmac_key"] | "";
  systemConfig.hmacDefaultKeyConfigured =
      hexStringToBytes(defaultHmacKeyStr, systemConfig.hmacDefaultKey, ICSN_HMAC_KEY_LEN);
  systemConfig.hmacPeerKeyCount = loadPeerKeys(
      icsnSecurity["peers"], "hmac_key", systemConfig.hmacPeerKeyEntries, MAX_PEER_KEY_ENTRIES);

  systemConfig.hmacAuthenticationEnabled =
      hmacEnabledFlag &&
      (systemConfig.hmacDefaultKeyConfigured || systemConfig.hmacPeerKeyCount > 0);
  if (hmacEnabledFlag && !systemConfig.hmacAuthenticationEnabled) {
    LOG_WARN("[WARN][SEC] config_invalid reason=hmac_key_missing");
  }
}

bool loadSystemConfig(const char* path) {
  if (!LittleFS.begin()) {
    LOG_WARN("[WARN][CFG] littlefs_mount_failed");
    return false;
  }

  File file = LittleFS.open(path, "r");
  if (!file) {
    LOG_WARNF("[WARN][CFG] config_open_failed path=%s\n", path != nullptr ? path : "(null)");
    return false;
  }

  // 2048バイトに拡張: fib_init配列（最大10エントリ）の追加によりメモリが増加
  StaticJsonDocument<2048> doc;
  const DeserializationError jsonError = deserializeJson(doc, file);
  if (jsonError) {
    LOG_WARNF("[WARN][CFG] config_parse_failed error=%s\n", jsonError.c_str());
    return false;
  }

  systemConfig.maxVirtualDepth = doc["MAX_VIRTUAL_DEPTH"] | 5;
  systemConfig.defaultInterestHopLimit = doc["default_interest_hop_limit"] | 10;

  resetSecurityConfig();
  if (doc.containsKey("esp_now_security") || doc.containsKey("icsn_security")) {
    loadSeparatedSecurityConfig(doc);
  } else {
    loadLegacySecurityConfig(doc);
  }

  // FIB初期エントリの読み込み
  systemConfig.fibInitCount = 0;
  memset(systemConfig.fibInitEntries, 0, sizeof(systemConfig.fibInitEntries));

  if (doc.containsKey("fib_init")) {
    JsonArray fibArray = doc["fib_init"].as<JsonArray>();
    for (JsonObject fibEntry : fibArray) {
      if (systemConfig.fibInitCount >= MAX_FIB_INIT_ENTRIES)
        break;

      const char* content = fibEntry["content"] | "";
      const char* nextHop = fibEntry["next_hop"] | "";

      if (strlen(content) > 0 && strlen(nextHop) > 0) {
        FibInitEntry& entry = systemConfig.fibInitEntries[systemConfig.fibInitCount];
        strncpy(entry.contentName, content, sizeof(entry.contentName) - 1);
        entry.contentName[sizeof(entry.contentName) - 1] = '\0';
        strncpy(entry.nextHopMac, nextHop, sizeof(entry.nextHopMac) - 1);
        entry.nextHopMac[sizeof(entry.nextHopMac) - 1] = '\0';
        entry.valid = true;
        systemConfig.fibInitCount++;
      }
    }
  }

  LOG_INFOF(
      "[INFO][CFG] config_loaded path=%s max_virtual_depth=%d hop_limit=%d fib_init_entries=%u\n",
      path != nullptr ? path : "(null)", systemConfig.maxVirtualDepth,
      systemConfig.defaultInterestHopLimit, static_cast<unsigned int>(systemConfig.fibInitCount));

  return true;
}
