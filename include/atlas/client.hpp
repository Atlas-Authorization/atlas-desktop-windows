// Protocol client, sync service and the signed-message builder.
#pragma once
#include "atlas/config.hpp"
#include "atlas/offline.hpp"

namespace atlas {

// atlas-desktop:v1:<purpose>:<instance id>:<key id>:<nonce>[:<extra>]
std::string signedMessage(const std::string& purpose, const std::string& instanceId, const std::string& keyId,
                          const std::string& nonce, const std::optional<std::string>& extra = std::nullopt);

struct ApiResult {
  int status = 0;
  json body;
  bool unreachable() const { return status == 0 || status >= 500; }
  bool ok() const { return status >= 200 && status < 300; }
  std::string errorCode() const;
  std::string deviceStatus() const;  // errors[0].meta.device_status
};

class Client {
 public:
  Client(const Config& cfg, IDeviceKey& key, IHttpClient& http) : cfg_(cfg), key_(key), http_(http) {}

  ApiResult enroll(const std::string& code, const std::string& pin, const std::string& hostname,
                   const std::string& platform, const std::string& agentVersion);
  ApiResult sync(const std::string& heldBundleId);
  ApiResult setPin(const std::string& pin);
  ApiResult startChallenge(const std::string& factor);
  ApiResult verify(const std::string& challengeId, const std::optional<std::string>& code,
                   const std::optional<json>& assertion);
  ApiResult report(const std::string& payload);

 private:
  ApiResult post(const std::string& path, const json& body);
  // Fetches a nonce, signs and posts. extra = the signed-message extra segment.
  ApiResult signedCall(const std::string& path, const std::string& purpose, const std::optional<std::string>& extra,
                       json body);
  const Config& cfg_;
  IDeviceKey& key_;
  IHttpClient& http_;
};

// What the last good sync told us; drives offline decisions. Stored as "sync_cache".
struct SyncCache {
  bool known = false, required = false, revoked = false, offlineEnabled = false, pinRequired = false;
  std::vector<std::string> factors;
  int64_t syncedAt = 0;
  json toJson() const;
  static SyncCache fromJson(const json& j);
};

namespace store {
constexpr const char* kMacKey = "mac_key";        // base64url string
constexpr const char* kSyncCache = "sync_cache";  // JSON
}  // namespace store

SyncCache loadSyncCache(ISecretStore& s);

enum class SyncOutcome { Ok, Revoked, Unreachable, Rejected };

class SyncService {
 public:
  SyncService(const Config&, Client& client, OfflineVault& vault, ISecretStore& store, IClock& clock)
      : client_(client), vault_(vault), store_(store), clock_(clock) {}
  SyncOutcome run();
  bool lastBundleRejected() const { return bundleRejected_; }

 private:
  void flushEvents();
  Client& client_;
  OfflineVault& vault_;
  ISecretStore& store_;
  IClock& clock_;
  bool bundleRejected_ = false;
};

struct EnrollResult {
  bool ok = false;
  std::string error, offlineOtpUri;
};
// Enrols, persists the bundle MAC key, and updates cfg (device_id, enrolled). The caller writes the config file.
EnrollResult enrollDevice(Config& cfg, IDeviceKey& key, IHttpClient& http, ISecretStore& store, const std::string& code,
                          const std::string& pin, const std::string& hostname, const std::string& platform,
                          const std::string& agentVersion);

}  // namespace atlas
