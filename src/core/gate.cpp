#include "atlas/gate.hpp"

#include <algorithm>
#include <cctype>

namespace atlas {

namespace {
bool supported(const std::string& f) { return f == "push" || f == "totp" || f == "passkey"; }
bool sixDigits(const std::string& c) {
  return c.size() == 6 && std::all_of(c.begin(), c.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; });
}
}  // namespace

GateDecision LoginGate::begin(bool passwordVerified) {
  satisfied_ = false;
  challengeId_.clear();
  challengeFactor_.clear();
  GateDecision d;
  if (!passwordVerified) { d.reason = "password_not_verified"; decision_ = d; return d; }
  if (!cfg_.enrolled) { d.kind = GateDecision::Kind::Denied; d.reason = "not_enrolled"; decision_ = d; return d; }

  SyncOutcome out = sync_.run();
  d.online = out == SyncOutcome::Ok;
  SyncCache c = loadSyncCache(store_);

  if (!c.known) {
    if (cfg_.failOpenWhenNeverSynced) { d.kind = GateDecision::Kind::NotRequired; satisfied_ = true; }
    else d.reason = "never_synced";
    decision_ = d;
    return d;
  }
  if (!c.required) {
    d.kind = GateDecision::Kind::NotRequired;
    satisfied_ = true;
    decision_ = d;
    return d;
  }
  if (c.revoked || out == SyncOutcome::Revoked) { d.reason = "revoked"; decision_ = d; return d; }

  OfflineResult st = c.offlineEnabled ? vault_.status() : OfflineResult::NoBundle;
  d.offlineAvailable = st == OfflineResult::Ok;
  d.offlinePinRequired = d.offlineAvailable && vault_.pinRequired();
  if (d.online) {
    for (const auto& f : c.factors)
      if (supported(f)) d.factors.push_back(f);
    if (d.factors.empty() && !d.offlineAvailable) { d.reason = "no_factor"; decision_ = d; return d; }
  } else if (!d.offlineAvailable) {
    d.reason = st == OfflineResult::Expired ? "offline_expired" : st == OfflineResult::ClockRollback ? "clock" : "offline_unavailable";
    decision_ = d;
    return d;
  }
  d.kind = GateDecision::Kind::Required;
  decision_ = d;
  return d;
}

StepResult LoginGate::finishVerify(const ApiResult& r) {
  if (r.unreachable()) return {Step::Unreachable, ""};
  if (r.status == 422) return {Step::WrongCode, ""};
  if (r.status == 429) { challengeId_.clear(); return {Step::Failed, "too_many_attempts"}; }
  if (!r.ok() || !r.body.is_object()) { challengeId_.clear(); return {Step::Failed, r.errorCode()}; }
  std::string s = r.body.value("status", "");
  if (s == "verified") { satisfied_ = true; lastVerified_ = challengeId_; challengeId_.clear(); return {Step::Verified, ""}; }
  if (s == "pending") return {Step::Pending, ""};
  challengeId_.clear();
  return {Step::Failed, "challenge_failed"};
}

StepResult LoginGate::startPush() {
  if (decision_.kind != GateDecision::Kind::Required || !decision_.online ||
      std::find(decision_.factors.begin(), decision_.factors.end(), "push") == decision_.factors.end())
    return {Step::Unsupported, "push_unavailable"};
  ApiResult r = client_.startChallenge("push");
  if (r.unreachable()) return {Step::Unreachable, ""};
  if (!r.ok() || !r.body.is_object() || !r.body.contains("id")) return {Step::Failed, r.errorCode()};
  challengeId_ = r.body["id"];
  challengeFactor_ = "push";
  return {Step::Pending, r.body.value("number_match", "")};
}

StepResult LoginGate::pollPush() {
  if (challengeId_.empty() || challengeFactor_ != "push") return {Step::Failed, "no_challenge"};
  return finishVerify(client_.verify(challengeId_, std::nullopt, std::nullopt));
}

StepResult LoginGate::submitCode(const std::string& code) {
  if (decision_.kind != GateDecision::Kind::Required || !decision_.online ||
      std::find(decision_.factors.begin(), decision_.factors.end(), "totp") == decision_.factors.end())
    return {Step::Unsupported, "totp_unavailable"};
  if (!sixDigits(code)) return {Step::WrongCode, ""};
  if (challengeId_.empty() || challengeFactor_ != "totp") {
    ApiResult s = client_.startChallenge("totp");
    if (s.unreachable()) return {Step::Unreachable, ""};
    if (!s.ok() || !s.body.is_object() || !s.body.contains("id")) return {Step::Failed, s.errorCode()};
    challengeId_ = s.body["id"];
    challengeFactor_ = "totp";
  }
  return finishVerify(client_.verify(challengeId_, code, std::nullopt));
}

StepResult LoginGate::startPasskey(json& optionsOut) {
  if (decision_.kind != GateDecision::Kind::Required || !decision_.online ||
      std::find(decision_.factors.begin(), decision_.factors.end(), "passkey") == decision_.factors.end())
    return {Step::Unsupported, "passkey_unavailable"};
  ApiResult s = client_.startChallenge("passkey");
  if (s.unreachable()) return {Step::Unreachable, ""};
  if (!s.ok() || !s.body.is_object() || !s.body.contains("id") || !s.body.contains("passkey_options"))
    return {Step::Failed, s.errorCode()};
  challengeId_ = s.body["id"];
  challengeFactor_ = "passkey";
  optionsOut = s.body["passkey_options"];
  return {Step::Pending, ""};
}

StepResult LoginGate::completePasskey(const std::optional<json>& assertion) {
  if (challengeId_.empty() || challengeFactor_ != "passkey") return {Step::Failed, "no_challenge"};
  if (!assertion) { challengeId_.clear(); return {Step::Failed, "cancelled"}; }
  StepResult r = finishVerify(client_.verify(challengeId_, std::nullopt, *assertion));
  // A rejected assertion spent its WebAuthn challenge: the next attempt starts a new one.
  if (r.step == Step::WrongCode) { challengeId_.clear(); return {Step::Failed, "passkey_rejected"}; }
  return r;
}

StepResult LoginGate::submitPasskey() {
  if (!passkey_) return {Step::Unsupported, "unsupported_in_this_build"};
  json options;
  StepResult s = startPasskey(options);
  if (s.step != Step::Pending) return s;
  return completePasskey(passkey_(options));
}

StepResult LoginGate::submitOffline(const std::string& pin, const std::string& code) {
  if (decision_.kind != GateDecision::Kind::Required || !decision_.offlineAvailable) return {Step::Unsupported, "offline_unavailable"};
  switch (vault_.unlock(pin, code)) {
    case OfflineResult::Ok: satisfied_ = true; return {Step::Verified, ""};
    case OfflineResult::WrongCredentials: return {Step::WrongCode, ""};
    case OfflineResult::Locked: return {Step::Locked, ""};
    case OfflineResult::Expired: return {Step::Failed, "offline_expired"};
    case OfflineResult::ClockRollback: return {Step::Failed, "clock"};
    default: return {Step::Failed, "offline_unavailable"};
  }
}

void LoginGate::reset() {
  satisfied_ = false;
  challengeId_.clear();
  challengeFactor_.clear();
  decision_ = GateDecision{};
}

}  // namespace atlas
