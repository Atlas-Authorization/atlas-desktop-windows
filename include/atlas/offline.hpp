// Offline bundle (MAC, ECIES open), PIN verifier, TOTP and the offline unlock state machine.
#pragma once
#include "atlas/base.hpp"

namespace atlas {

struct Bundle {
  std::string bundleId;
  int64_t generation = 0;
  int64_t issuedAt = 0;
  int64_t expiresAt = 0;
  std::string sealed;
  std::string mac;
  json toJson() const;
  static std::optional<Bundle> fromJson(const json& j);
};

// base64url(HMAC-SHA256(macKey, "atlas-desktop-bundle:v1:" + device_id + ":" + bundle_id + ":" + generation + ":" + expires_at + ":" + sealed))
std::string bundleMac(const Bytes& macKey, const std::string& deviceId, const Bundle& b);
bool bundleMacOk(const Bytes& macKey, const std::string& deviceId, const Bundle& b);

struct PinVerifier {
  uint64_t N = 0, r = 0, p = 0;
  std::string salt, hash;  // base64url
};
struct TotpSpec {
  std::string secret;  // base32
  int digits = 6;
  int period = 30;
  std::string algorithm;
};
struct BundlePlain {
  std::string bundleId, deviceId, userId;
  int64_t generation = 0, issuedAt = 0, expiresAt = 0;
  bool pinRequired = false;
  std::optional<PinVerifier> pin;
  TotpSpec totp;
};

// ECIES open per PROTOCOL.md. nullopt on any structural, ECDH or AES-GCM failure.
std::optional<BundlePlain> openBundle(IDeviceKey& key, const std::string& sealed);
bool verifyPin(const std::string& pin, const PinVerifier& v);

std::string totpCode(const std::string& base32Secret, int64_t unixSeconds, int digits = 6, int period = 30);
// Accepts steps now-1..now+1 that are > lastStep. Returns the matched step.
std::optional<int64_t> totpMatch(const std::string& base32Secret, const std::string& code, int64_t unixSeconds,
                                 int64_t lastStep);

enum class OfflineResult { Ok, NoBundle, BundleInvalid, Expired, ClockRollback, Locked, WrongCredentials };

struct OfflineEvent {
  int64_t at = 0;
  std::string outcome;  // "success" | "failure"
  std::string bundleId;
  std::string reason;
};

// Persistent offline state: the held bundle, attempt counter and lock, replay mark, clock high-water, event queue.
class OfflineVault {
 public:
  static constexpr int kMaxAttempts = 5;
  static constexpr int64_t kLockMs = 15 * 60 * 1000;
  static constexpr int64_t kClockSlackMs = 5 * 60 * 1000;
  static constexpr size_t kMaxQueuedEvents = 1000;

  OfflineVault(ISecretStore& store, IClock& clock, IDeviceKey& key, std::string deviceId);

  // Verifies the MAC against the stored mac key before storing. False (and nothing stored) otherwise.
  bool storeBundle(const Bundle& b);
  std::optional<Bundle> heldBundle();
  void wipe();  // drops the bundle (keeps the attempt log and lock)
  void noteTime();  // advance the monotonic high-water mark
  // Usable now: present, MAC ok, opens, bound to this device, within its validity and clock sane.
  OfflineResult status();
  bool pinRequired();  // of the held bundle; false if none
  OfflineResult unlock(const std::string& pin, const std::string& code);

  std::vector<OfflineEvent> events();
  void dropEvents(size_t n);  // drop the oldest n after a successful report

 private:
  struct State {
    int fails = 0;
    int64_t lockUntil = 0, lastStep = -1, highWater = 0;
    std::vector<OfflineEvent> events;
  };
  State load();
  void save(const State& s);
  OfflineResult check(State& s, BundlePlain& plain, int64_t now);

  ISecretStore& store_;
  IClock& clock_;
  IDeviceKey& key_;
  std::string deviceId_;
};

}  // namespace atlas
