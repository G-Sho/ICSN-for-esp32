#include "ESP-NOWController.hpp"
#include "BuildProfile.hpp"
#include "config/Config.hpp"
#include "message/SignalCode.hpp"

#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>

#include <algorithm>
#include <cstring> // strncpy用
#include <iomanip>
#include <sstream>
#include <string>

static std::string addressToString(const uint8_t* address);

ESP_NOWController::ESP_NOWController(IInputBoundary& inputBoundary,
                                     IForwardingStateBoundary& forwardingStateBoundary)
    : inputBoundary(inputBoundary), forwardingStateBoundary(forwardingStateBoundary) {}

bool ESP_NOWController::loadAndApplyConfig(const char* configPath) {
  if (!loadSystemConfig(configPath)) {
    LOG_WARNF("[WARN][CFG] config_load_failed path=%s\n",
              configPath != nullptr ? configPath : "(null)");
    return false;
  }

  espNowEncryptionEnabled = systemConfig.espNowEncryptionEnabled;
  hmacAuthenticationEnabled = systemConfig.hmacAuthenticationEnabled;
  memset(pmk, 0, sizeof(pmk));

  if (espNowEncryptionEnabled && systemConfig.espNowPmkConfigured) {
    memcpy(pmk, systemConfig.espNowPmk, sizeof(pmk));
  }

  if (hmacAuthenticationEnabled && systemConfig.hmacDefaultKeyConfigured) {
    setGlobalLMK(systemConfig.hmacDefaultKey);
    LOG_INFO("[INFO][SEC] hmac_default_key_configured");
  }

  for (size_t i = 0; i < systemConfig.hmacPeerKeyCount; i++) {
    const PeerKeyConfig& entry = systemConfig.hmacPeerKeyEntries[i];
    if (entry.valid) {
      setPeerLMK(entry.mac, entry.key);
    }
  }

  for (size_t i = 0; i < systemConfig.fibInitCount; i++) {
    const FibInitEntry& entry = systemConfig.fibInitEntries[i];
    if (entry.valid) {
      initFIBEntry(std::string(entry.contentName), std::string(entry.nextHopMac));
      LOG_INFOF("[INFO][CFG] fib_init_applied name=%s next_hop=%s\n", entry.contentName,
                entry.nextHopMac);
    }
  }

  return true;
}

bool ESP_NOWController::copyPMK(uint8_t* outPmk, size_t outLen) const {
  if (outPmk == nullptr || outLen < sizeof(pmk) || !espNowEncryptionEnabled) {
    return false;
  }

  memcpy(outPmk, pmk, sizeof(pmk));
  return true;
}

bool ESP_NOWController::initializeCommunication(const char* configPath, uint8_t myMac[6],
                                                esp_now_recv_cb_t recvCb, esp_now_send_cb_t sendCb,
                                                uint8_t channel) {
  if (myMac == nullptr || recvCb == nullptr || sendCb == nullptr) {
    LOG_WARN("[WARN][ESPNOW] init_failed reason=invalid_arguments");
    return false;
  }

  if (!loadAndApplyConfig(configPath)) {
    LOG_WARN("[WARN][ESPNOW] init_failed reason=config_load_failed");
    return false;
  }

  WiFi.mode(WIFI_STA);
  esp_err_t channelErr = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  if (channelErr != ESP_OK) {
    LOG_WARNF("[WARN][ESPNOW] init_failed reason=set_channel_failed channel=%u error=%d\n", channel,
              channelErr);
    return false;
  }

  if (esp_now_init() != ESP_OK) {
    LOG_WARN("[WARN][ESPNOW] init_failed reason=esp_now_init_failed");
    return false;
  }

  uint8_t localPmk[PMK_LENGTH] = {0};
  if (copyPMK(localPmk, sizeof(localPmk))) {
    if (esp_now_set_pmk(localPmk) != ESP_OK) {
      LOG_WARN("[WARN][SEC] init_failed reason=pmk_set_failed");
      return false;
    }
    LOG_INFO("[INFO][SEC] pmk_configured");
  }

  if (hmacAuthenticationEnabled) {
    LOG_INFO("[INFO][SEC] hmac_enabled");
  }

  if (!registerConfiguredEspNowPeers()) {
    LOG_WARN("[WARN][ESPNOW] init_failed reason=configured_peer_registration_failed");
    return false;
  }

  esp_err_t macErr = esp_wifi_get_mac(WIFI_IF_STA, myMac);
  if (macErr != ESP_OK) {
    memset(myMac, 0, 6);
    LOG_WARNF("[WARN][ESPNOW] init_failed reason=get_mac_failed error=%d\n", macErr);
    return false;
  }

  esp_now_register_send_cb(sendCb);
  esp_now_register_recv_cb(recvCb);

  LOG_INFOF("[INFO][ESPNOW] initialized channel=%u\n", channel);
  return true;
}

bool ESP_NOWController::registerPeerIfNeeded(const uint8_t mac[6]) {
  if (mac == nullptr || esp_now_is_peer_exist(mac)) {
    return true;
  }

  const std::string peerStr = addressToString(mac);

  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, mac, 6);
  peer.channel = 0;
  peer.ifidx = WIFI_IF_STA;

  if (espNowEncryptionEnabled && !isBroadcastOrMulticast(mac)) {
    const uint8_t* lmk = resolveEspNowLmk(mac);
    if (lmk == nullptr) {
      LOG_WARNF("[WARN][SEC] peer_registration_failed reason=lmk_missing peer=%s\n",
                peerStr.c_str());
      return false;
    }
    memcpy(peer.lmk, lmk, PEER_LMK_LEN);
    peer.encrypt = true;
  } else {
    peer.encrypt = false;
  }

  if (esp_now_add_peer(&peer) != ESP_OK) {
    LOG_WARNF("[WARN][ESPNOW] peer_registration_failed peer=%s\n", peerStr.c_str());
    return false;
  }

  LOG_DEBUGF("[DEBUG][ESPNOW] peer_registered peer=%s\n", peerStr.c_str());
  return true;
}

bool ESP_NOWController::sendPacketToAddresses(const ESP_NOWControlData& data) {
  bool sentAny = false;

  for (const auto& addr : data.txAddress) {
    if (std::all_of(addr.begin(), addr.end(), [](uint8_t b) { return b == 0; })) {
      continue;
    }

    const std::string peerStr = addressToString(addr.data());
    LOG_DEBUGF("[DEBUG][TX] packet_queued peer=%s type=%s name=%s hop=%u\n", peerStr.c_str(),
               data.signalCode, data.contentName, static_cast<unsigned int>(data.hopCount));

    CommunicationData packet = {};
    if (!buildPacketForAddress(addr.data(), data, true, packet)) {
      LOG_WARNF("[WARN][TX] packet_build_failed peer=%s reason=security_build_failed\n",
                peerStr.c_str());
      continue;
    }

    if (!registerPeerIfNeeded(addr.data())) {
      LOG_WARNF("[WARN][TX] send_rejected peer=%s reason=peer_registration_failed\n",
                peerStr.c_str());
      continue;
    }

    esp_err_t err =
        esp_now_send(addr.data(), reinterpret_cast<const uint8_t*>(&packet), sizeof(packet));
    if (err != ESP_OK) {
      LOG_WARNF("[WARN][TX] send_rejected peer=%s error=%d\n", peerStr.c_str(), err);
      continue;
    }

    sentAny = true;
  }

  return sentAny;
}

bool ESP_NOWController::registerConfiguredEspNowPeers() {
  bool allRegistered = true;

  for (size_t i = 0; i < systemConfig.espNowPeerLmkCount; i++) {
    const PeerKeyConfig& entry = systemConfig.espNowPeerLmkEntries[i];
    if (!entry.valid) {
      continue;
    }

    if (!registerPeerIfNeeded(entry.mac)) {
      allRegistered = false;
    }
  }

  return allRegistered;
}

bool ESP_NOWController::sendSensorData(const char* contentName, const char* content,
                                       uint8_t hopLimit) {
  if (contentName == nullptr || content == nullptr) {
    return false;
  }

  ESP_NOWControlData sensorData = {};
  sensorData.hopCount = hopLimit;
  strncpy(sensorData.signalCode, "DATA", MAX_SIGNAL_CODE_LENGTH - 1);
  sensorData.signalCode[MAX_SIGNAL_CODE_LENGTH - 1] = '\0';
  strncpy(sensorData.contentName, contentName, MAX_CONTENT_NAME_LENGTH - 1);
  sensorData.contentName[MAX_CONTENT_NAME_LENGTH - 1] = '\0';
  strncpy(sensorData.content, content, MAX_CONTENT_LENGTH - 1);
  sensorData.content[MAX_CONTENT_LENGTH - 1] = '\0';

  receiveSensorData(sensorData);
  return true;
}

bool ESP_NOWController::sendInterest(const char* contentName, const uint8_t* targetMac,
                                     uint8_t hopLimit) {
  if (contentName == nullptr || targetMac == nullptr) {
    return false;
  }

  ESP_NOWControlData interest = {};
  std::copy(targetMac, targetMac + 6, interest.txAddress[0].begin());

  strncpy(interest.signalCode, "INTEREST", MAX_SIGNAL_CODE_LENGTH - 1);
  interest.signalCode[MAX_SIGNAL_CODE_LENGTH - 1] = '\0';
  interest.hopCount = hopLimit;
  strncpy(interest.contentName, contentName, MAX_CONTENT_NAME_LENGTH - 1);
  interest.contentName[MAX_CONTENT_NAME_LENGTH - 1] = '\0';
  strncpy(interest.content, "N/A", MAX_CONTENT_LENGTH - 1);
  interest.content[MAX_CONTENT_LENGTH - 1] = '\0';

  return sendPacketToAddresses(interest);
}

bool ESP_NOWController::processReceivedPacket(const uint8_t myMac[6], const uint8_t senderMac[6],
                                              const uint8_t* data, int len,
                                              ReceiveProcessResult* result) {
  ReceiveProcessResult localResult;
  ReceiveProcessResult& out = (result == nullptr) ? localResult : *result;
  out = {};

  if (myMac == nullptr || senderMac == nullptr || data == nullptr) {
    LOG_WARN("[WARN][RX] packet_dropped reason=invalid_arguments");
    return false;
  }

  const std::string senderStr = addressToString(senderMac);
  LOG_DEBUGF("[DEBUG][RX] packet_received peer=%s bytes=%d\n", senderStr.c_str(), len);

  if (len != static_cast<int>(sizeof(CommunicationData))) {
    LOG_WARNF("[WARN][RX] packet_dropped reason=invalid_length peer=%s actual=%d expected=%u\n",
              senderStr.c_str(), len, static_cast<unsigned int>(sizeof(CommunicationData)));
    return false;
  }

  if (!registerPeerIfNeeded(senderMac)) {
    LOG_WARNF("[WARN][RX] packet_dropped reason=peer_registration_failed peer=%s\n",
              senderStr.c_str());
    return false;
  }

  CommunicationData receivedPacket = {};
  memcpy(&receivedPacket, data, sizeof(receivedPacket));
  out.validPacket = true;

  out.isInterest = (strncmp(receivedPacket.signalCode, "INTEREST", MAX_SIGNAL_CODE_LENGTH) == 0);
  out.isData = (strncmp(receivedPacket.signalCode, "DATA", MAX_SIGNAL_CODE_LENGTH) == 0);

#if ICSN_PERF_ENABLED
  if (out.isInterest) {
    interestTiming.recordInterestRx();
  }
#endif

  out.securityCheckRequired = hmacAuthenticationEnabled;
  if (out.securityCheckRequired) {
#if ICSN_PERF_ENABLED
    if (out.isInterest) {
      interestTiming.recordSecurityCheckStart();
    }
#endif
    out.securityCheckVerified = verifyIncomingPacket(senderMac, receivedPacket);
    if (!out.securityCheckVerified) {
      LOG_WARNF("[WARN][RX] packet_dropped reason=security_verification_failed peer=%s\n",
                senderStr.c_str());
      return false;
    }

#if ICSN_PERF_ENABLED
    if (out.isInterest) {
      interestTiming.recordSecurityCheckEnd();
    }
#endif
  }

  LOG_DEBUGF("[DEBUG][RX] packet_accepted peer=%s type=%s name=%s hop=%u\n", senderStr.c_str(),
             receivedPacket.signalCode, receivedPacket.contentName,
             static_cast<unsigned int>(receivedPacket.hopCount));

  ESP_NOWControlData inputData = {};
  strncpy(inputData.signalCode, receivedPacket.signalCode, MAX_SIGNAL_CODE_LENGTH - 1);
  inputData.signalCode[MAX_SIGNAL_CODE_LENGTH - 1] = '\0';
  inputData.hopCount = receivedPacket.hopCount;
  strncpy(inputData.contentName, receivedPacket.contentName, MAX_CONTENT_NAME_LENGTH - 1);
  inputData.contentName[MAX_CONTENT_NAME_LENGTH - 1] = '\0';
  strncpy(inputData.content, receivedPacket.content, MAX_CONTENT_LENGTH - 1);
  inputData.content[MAX_CONTENT_LENGTH - 1] = '\0';
  std::copy(senderMac, senderMac + 6, inputData.txAddress[0].begin());

  ESP_NOWControlData outputData = receiveMessage(myMac, senderMac, inputData);

#if ICSN_PERF_ENABLED
  if (out.isInterest) {
    interestTiming.recordFibLookup();
  }
#endif

  out.forwarded = sendPacketToAddresses(outputData);

#if ICSN_PERF_ENABLED
  if (out.isInterest && out.forwarded) {
    interestTiming.recordForwardTx();
  }
#endif

  return true;
}

// ヘルパー: アドレスをログ用のstd::stringに変換
static std::string addressToString(const uint8_t* address) {
  if (address == nullptr) {
    return "na";
  }

  std::ostringstream oss;
  for (int i = 0; i < 6; ++i) {
    if (i > 0)
      oss << ":";
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(address[i]);
  }
  return oss.str();
}

std::array<uint8_t, 6> macStringToArray(const std::string& macStr) {
  std::array<uint8_t, 6> mac{};
  unsigned int values[6];

  if (sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3],
             &values[4], &values[5]) == 6) {
    for (int i = 0; i < 6; ++i) {
      mac[i] = static_cast<uint8_t>(values[i]);
    }
  }
  return mac;
}

ESP_NOWControlData ESP_NOWController::receiveMessage(const uint8_t rxAddress[6],
                                                     const uint8_t txAddress[6],
                                                     const ESP_NOWControlData& data) {
  std::string rxAddrStr = addressToString(rxAddress);
  std::string txAddrStr = addressToString(txAddress);

  SignalCode code = fromString(data.signalCode);

  InputData inputData(txAddrStr, {rxAddrStr}, std::string(data.signalCode),
                      static_cast<int>(data.hopCount), std::string(data.contentName),
                      std::string(data.content));

  OutputData outputData;

  if (code == SignalCode::INTEREST) {
    outputData = inputBoundary.handleInterestReceive(inputData);
  } else if (code == SignalCode::DATA) {
    outputData = inputBoundary.handleDataReceive(inputData);
  } else {
    LOG_WARNF("[WARN][RX] packet_dropped reason=unknown_signal peer=%s type=%s\n",
              txAddrStr.c_str(), data.signalCode);
    return ESP_NOWControlData{};
  }

  ESP_NOWControlData result = {};

  // 最大MAX_TX_ADDRESSES個までMACアドレスをコピー
  int index = 0;
  for (const auto& addrStr : outputData.destId) {
    if (index >= MAX_TX_ADDRESSES)
      break;
    result.txAddress[index] = macStringToArray(addrStr);
    index++;
  }

  // char配列への安全なコピー
  strncpy(result.signalCode, outputData.signalCode.c_str(), MAX_SIGNAL_CODE_LENGTH - 1);
  result.signalCode[MAX_SIGNAL_CODE_LENGTH - 1] = '\0';

  result.hopCount = outputData.hopCount;

  strncpy(result.contentName, outputData.contentName.c_str(), MAX_CONTENT_NAME_LENGTH - 1);
  result.contentName[MAX_CONTENT_NAME_LENGTH - 1] = '\0';

  strncpy(result.content, outputData.content.c_str(), MAX_CONTENT_LENGTH - 1);
  result.content[MAX_CONTENT_LENGTH - 1] = '\0';

  return result;
}

void ESP_NOWController::receiveSensorData(const ESP_NOWControlData& data) {
  LOG_INFOF("[INFO][RX] sensor_data_received name=%s\n", data.contentName);

  InputData inputData(std::string("N/A"), // senderId: 仮
                      {},                 // destId: 空
                      std::string(data.signalCode),
                      0, // hopCount: 空
                      std::string(data.contentName), std::string(data.content));

  inputBoundary.handleSensorDataReceive(inputData);
}

void ESP_NOWController::setGlobalLMK(const uint8_t lmk[PEER_LMK_LEN]) {
  peerCounterManager.setGlobalLMK(lmk);
}

bool ESP_NOWController::setPeerLMK(const uint8_t mac[6], const uint8_t lmk[PEER_LMK_LEN]) {
  return peerCounterManager.setPeerLMK(mac, lmk);
}

bool ESP_NOWController::buildPacketForAddress(const uint8_t txAddress[6],
                                              const ESP_NOWControlData& data, bool applySecurity,
                                              CommunicationData& outPacket) {
  memset(&outPacket, 0, sizeof(CommunicationData));

  strncpy(outPacket.signalCode, data.signalCode, MAX_SIGNAL_CODE_LENGTH - 1);
  outPacket.signalCode[MAX_SIGNAL_CODE_LENGTH - 1] = '\0';
  outPacket.hopCount = data.hopCount;
  strncpy(outPacket.contentName, data.contentName, MAX_CONTENT_NAME_LENGTH - 1);
  outPacket.contentName[MAX_CONTENT_NAME_LENGTH - 1] = '\0';
  strncpy(outPacket.content, data.content, MAX_CONTENT_LENGTH - 1);
  outPacket.content[MAX_CONTENT_LENGTH - 1] = '\0';

  if (!applySecurity) {
    outPacket.counter = 0;
    memset(outPacket.hmac, 0, sizeof(outPacket.hmac));
    return true;
  }

  bool counterSuccess = false;
  outPacket.counter = peerCounterManager.incrementTxCounter(txAddress, counterSuccess);
  if (!counterSuccess) {
    LOG_WARNF("[WARN][TX] packet_build_failed peer=%s reason=counter_increment_failed\n",
              addressToString(txAddress).c_str());
    return false;
  }

  memset(outPacket.hmac, 0, sizeof(outPacket.hmac));
  if (!peerCounterManager.computeHMAC(txAddress, reinterpret_cast<const uint8_t*>(&outPacket),
                                      COMM_DATA_HMAC_DATA_LEN, outPacket.hmac)) {
    LOG_WARNF("[WARN][SEC] packet_build_failed reason=hmac_compute_failed peer=%s\n",
              addressToString(txAddress).c_str());
    return false;
  }

  return true;
}

bool ESP_NOWController::verifyIncomingPacket(const uint8_t mac[6],
                                             const CommunicationData& packet) {
  if (!hmacAuthenticationEnabled) {
    return true;
  }

  if (!peerCounterManager.verifyHMAC(mac, reinterpret_cast<const uint8_t*>(&packet),
                                     COMM_DATA_HMAC_DATA_LEN, packet.hmac)) {
    LOG_WARNF("[WARN][SEC] packet_dropped reason=hmac_failed peer=%s\n",
              addressToString(mac).c_str());
    return false;
  }

  if (!peerCounterManager.validateRxCounter(mac, packet.counter)) {
    LOG_WARNF("[WARN][SEC] packet_dropped reason=replay_detected peer=%s counter=%lu\n",
              addressToString(mac).c_str(), (unsigned long)packet.counter);
    return false;
  }

  return true;
}

const uint8_t* ESP_NOWController::resolveEspNowLmk(const uint8_t mac[6]) const {
  if (mac == nullptr) {
    return nullptr;
  }

  for (size_t i = 0; i < systemConfig.espNowPeerLmkCount; i++) {
    const PeerKeyConfig& entry = systemConfig.espNowPeerLmkEntries[i];
    if (entry.valid && memcmp(entry.mac, mac, 6) == 0) {
      return entry.key;
    }
  }

  if (systemConfig.espNowDefaultLmkConfigured) {
    return systemConfig.espNowDefaultLmk;
  }

  return nullptr;
}

bool ESP_NOWController::isBroadcastOrMulticast(const uint8_t mac[6]) const {
  if (mac == nullptr) {
    return false;
  }

  bool allFF = true;
  for (size_t i = 0; i < 6; i++) {
    if (mac[i] != 0xFF) {
      allFF = false;
      break;
    }
  }

  if (allFF) {
    return true;
  }

  return (mac[0] & 0x01) != 0;
}

void ESP_NOWController::printCounters() const {
  peerCounterManager.printCounters();
}

void ESP_NOWController::initFIBEntry(const std::string& contentName,
                                     const std::string& nextHopMac) {
  forwardingStateBoundary.initFIBEntry(contentName, nextHopMac);
}

void ESP_NOWController::printFIB() const {
  forwardingStateBoundary.printFIB();
}

void ESP_NOWController::clearCSCache() {
  forwardingStateBoundary.clearCSCache();
}

void ESP_NOWController::clearPITCache() {
  forwardingStateBoundary.clearPITCache();
}

void ESP_NOWController::dumpPerformanceData() const {
#if !ICSN_PERF_ENABLED
  CLI_PRINTLN("{\"error\": \"perf_build_required\"}");
  return;
#else
  uint16_t cnt = interestTiming.getCount();
  CLI_PRINTLN("{");
  CLI_PRINTLN("  \"measurements\": [");
  for (uint16_t i = 0; i < cnt; i++) {
    const InterestPacketTimingEntry& m = interestTiming.getEntry(i);
    const char* separator = (i < cnt - 1) ? "," : "";
    uint32_t security_check_us = m.security_check_end_us - m.security_check_start_us;
    uint32_t fib_us = (m.security_check_end_us > 0) ? m.fib_lookup_us - m.security_check_end_us
                                                    : m.fib_lookup_us - m.interest_rx_us;
    uint32_t total_us = m.forward_tx_us - m.interest_rx_us;
    CLI_PRINTF(
        "    {\"i\": %u, \"security_check_us\": %lu, \"fib_us\": %lu, \"total_us\": %lu}%s\n",
        static_cast<unsigned>(i), static_cast<unsigned long>(security_check_us),
        static_cast<unsigned long>(fib_us), static_cast<unsigned long>(total_us), separator);
  }
  CLI_PRINTLN("  ]");
  CLI_PRINTLN("}");
#endif
}

void ESP_NOWController::resetPerformanceData() {
#if !ICSN_PERF_ENABLED
  CLI_PRINTLN("{\"error\": \"perf_build_required\"}");
#else
  interestTiming.reset();
  CLI_PRINTLN("{\"status\": \"perf_reset\"}");
#endif
}

void ESP_NOWController::printPerformanceCount() const {
#if !ICSN_PERF_ENABLED
  CLI_PRINTLN("{\"error\": \"perf_build_required\"}");
#else
  CLI_PRINTF("{\"count\": %u}\n", static_cast<unsigned>(interestTiming.getCount()));
#endif
}
