// LoginGate: decides whether a second factor is needed and runs the factor flow. Non-blocking:
// the host (credential provider) calls the step functions from its UI events and a poll timer.
#pragma once
#include "atlas/client.hpp"

#include <functional>

namespace atlas {

struct GateDecision {
  enum class Kind { NotRequired, Required, Denied } kind = Kind::Denied;
  bool online = false;  // server answered this attempt
  std::vector<std::string> factors;  // usable online factors (push, totp, passkey)
  bool offlineAvailable = false;     // a usable offline bundle is held
  bool offlinePinRequired = false;
  std::string reason;                // set when Denied: never_synced, revoked, no_factor, offline_unavailable, offline_expired, clock
};

enum class Step { Verified, Pending, WrongCode, Failed, Locked, Unsupported, Unreachable };
struct StepResult {
  Step step = Step::Failed;
  std::string detail;  // number match for a started push; reason code otherwise
};

class LoginGate {
 public:
  using PasskeyFn = std::function<std::optional<json>(const json& passkeyOptions)>;

  LoginGate(const Config& cfg, Client& client, SyncService& sync, OfflineVault& vault, ISecretStore& store)
      : cfg_(cfg), client_(client), sync_(sync), vault_(vault), store_(store) {}

  void setPasskeyHandler(PasskeyFn fn) { passkey_ = std::move(fn); }

  GateDecision begin();  // best-effort sync, then decide from the (fresh or cached) state
  StepResult startPush();  // detail = the number to display
  StepResult pollPush();
  StepResult submitCode(const std::string& code);  // online TOTP
  StepResult submitPasskey();
  StepResult submitOffline(const std::string& pin, const std::string& code);

  bool satisfied() const { return satisfied_; }
  void reset();  // call after the serialization was handed out and on deselect

 private:
  StepResult finishVerify(const ApiResult& r);
  const Config& cfg_;
  Client& client_;
  SyncService& sync_;
  OfflineVault& vault_;
  ISecretStore& store_;
  PasskeyFn passkey_;
  bool satisfied_ = false;
  std::string challengeId_, challengeFactor_;
  GateDecision decision_;
};

}  // namespace atlas
