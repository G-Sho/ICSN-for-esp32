#include "UseCaseInteractor.hpp"
#include "BuildProfile.hpp"
#include "config/Config.hpp"
#include "interface/data_access/IRIB.hpp"
#include "message/Content.hpp"
#include "message/ContentName.hpp"
#include "message/DestinationId.hpp"
#include "message/HopCount.hpp"
#include "message/SenderId.hpp"
#include "message/SignalCode.hpp"

UseCaseInteractor::UseCaseInteractor(IForwardingInformationBase& fibRepository,
                                     IPendingInterestTable& pitRepository,
                                     IContentStore& csRepository, IRIB& ribRepository)
    : fibRepository(fibRepository), pitRepository(pitRepository), csRepository(csRepository),
      ribRepository(ribRepository) {}

/// @brief Interestパケットを受信したときの処理
/// @param inputData 入力された Interest データ構造
/// @return 応答パケット（DATA, INTEREST, INVALID）
OutputData UseCaseInteractor::handleInterestReceive(const InputData& inputData) {
  SenderId senderId(inputData.senderId);
  DestinationId destinationId({inputData.destId});
  HopCount hopcount(inputData.hopCount);
  ContentName contentName(inputData.contentName);
  Content content(inputData.content);

  // INTEREST受信時の処理
  // ホップカウントチェック（転送時の値で判定）
  if (hopcount.getValue() + 1 >= systemConfig.hopCountThreshold) {
    LOG_DEBUGF("[DEBUG][UC] interest_dropped reason=hop_limit name=%s hop=%d limit=%d\n",
               contentName.getValue().c_str(), hopcount.getValue() + 1,
               systemConfig.hopCountThreshold);
    // パケット破棄
    return makeOutput(VALUE_NA, {VALUE_NA}, toString(SignalCode::INVALID), hopcount.getValue() + 1,
                      VALUE_NA, VALUE_NA);
  }

  if (csRepository.find(contentName)) {
    LOG_DEBUGF("[DEBUG][UC] interest_cs_hit name=%s\n", contentName.getValue().c_str());
    Content res = csRepository.get(contentName);
    // CSからデータ送信 (新しいDATAパケットなのでホップ数=0)
    LOG_DEBUGF("[DEBUG][UC] data_forward name=%s requesters=1\n", contentName.getValue().c_str());
    return makeOutput(*destinationId.getValue().begin(), {senderId.getValue()},
                      toString(SignalCode::DATA), 0, contentName.getValue(), res.getValue());
  } else {
    LOG_DEBUGF("[DEBUG][UC] interest_cs_miss name=%s\n", contentName.getValue().c_str());

    // PITテーブルに保存
    PITPair pitPair(contentName, DestinationId({senderId.getValue()}));
    pitRepository.save(pitPair);
    LOG_DEBUGF("[DEBUG][UC] interest_requester_saved name=%s requester=%s\n",
               contentName.getValue().c_str(), senderId.getValue().c_str());

    if (fibRepository.find(contentName)) {
      const DestinationId nextHops = fibRepository.get(contentName);
      LOG_DEBUGF("[DEBUG][UC] interest_forward name=%s hop=%d next_hops=%u\n",
                 contentName.getValue().c_str(), hopcount.getValue() + 1,
                 static_cast<unsigned int>(nextHops.getValue().size()));
      // FIBテーブルに基づいてINTEREST送信 (転送なのでホップ数+1)
      return makeOutput(*destinationId.getValue().begin(), nextHops.getValue(),
                        toString(SignalCode::INTEREST), hopcount.getValue() + 1,
                        contentName.getValue(), content.getValue());
    } else {
      LOG_DEBUGF("[DEBUG][UC] interest_dropped reason=fib_miss name=%s\n",
                 contentName.getValue().c_str());
      // FIB未ヒット時はブロードキャストせず破棄
      return makeOutput(VALUE_NA, {VALUE_NA}, toString(SignalCode::INVALID),
                        hopcount.getValue() + 1, VALUE_NA, VALUE_NA);
    }
  }
};

/// @brief Dataパケットを受信したときの処理
/// @param inputData 入力された Data データ構造
/// @return 応答パケット（DATA, INVALID）
OutputData UseCaseInteractor::handleDataReceive(const InputData& inputData) {
  HopCount hopcount(inputData.hopCount);
  ContentName contentName(inputData.contentName);
  Content content(inputData.content);

  // DATA受信時の処理
  if (pitRepository.find(contentName)) {
    const DestinationId requesters = pitRepository.get(contentName);

    pitRepository.remove(contentName);

    // CSにキャッシュ
    CSPair csPair(contentName, content);
    csRepository.save(csPair);
    LOG_DEBUGF("[DEBUG][UC] data_cached name=%s\n", contentName.getValue().c_str());

    LOG_DEBUGF("[DEBUG][UC] data_forward name=%s requesters=%u\n", contentName.getValue().c_str(),
               static_cast<unsigned int>(requesters.getValue().size()));

    const std::string origin = inputData.destId.empty() ? VALUE_NA : *inputData.destId.begin();

    // PITに基づいてデータ送信 (転送なのでホップ数+1)
    return makeOutput(origin, requesters.getValue(), toString(SignalCode::DATA),
                      hopcount.getValue() + 1, contentName.getValue(), content.getValue());
  } else {
    LOG_DEBUGF("[DEBUG][UC] data_dropped reason=pit_miss name=%s\n",
               contentName.getValue().c_str());
    // パケット破棄 (対応するINTERESTがない)
    return makeOutput(VALUE_NA, {VALUE_NA}, toString(SignalCode::INVALID), hopcount.getValue() + 1,
                      VALUE_NA, VALUE_NA);
  }
};

/// @brief センサーデータを受信したときの処理
/// @details センサーデータはCSに保存されるだけで、応答は生成されない。
/// @param inputData 入力されたセンサーデータ構造
void UseCaseInteractor::handleSensorDataReceive(const InputData& inputData) {
  ContentName contentName(inputData.contentName);
  Content content(inputData.content);
  CSPair csPair(contentName, content);
  csRepository.save(csPair);
  LOG_DEBUGF("[DEBUG][UC] sensor_cached name=%s\n", contentName.getValue().c_str());

  // csRepository.printCache();
}

/// @brief FIBに初期エントリを投入する
/// @param contentName コンテンツ名プレフィックス
/// @param nextHopMac 次ホップのMACアドレス文字列（小文字コロン区切り）
void UseCaseInteractor::initFIBEntry(const std::string& contentName,
                                     const std::string& nextHopMac) {
  ribRepository.addRoute(contentName, nextHopMac);
}

/// @brief FIBの内容をシリアルに出力する
void UseCaseInteractor::printFIB() const {
  fibRepository.printCache();
}

/// @brief Content Store をクリアする
void UseCaseInteractor::clearCSCache() {
  csRepository.clear();
  CLI_PRINTLN("[CACHE] Content Store cleared");
}

/// @brief PIT をクリアする
void UseCaseInteractor::clearPITCache() {
  pitRepository.clear();
  CLI_PRINTLN("[CACHE] PIT cleared");
}
