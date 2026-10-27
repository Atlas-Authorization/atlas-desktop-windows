#include "atlas/client.hpp"

namespace atlas {

std::string signedMessage(const std::string& purpose, const std::string& instanceId, const std::string& keyId,
                          const std::string& nonce, const std::optional<std::string>& extra) {
  std::string m = "atlas-desktop:v1:" + purpose + ":" + instanceId + ":" + keyId + ":" + nonce;
  if (extra) m += ":" + *extra;
  return m;
}

std::string ApiResult::errorCode() const {
  if (body.is_object() && body.contains("errors") && body["errors"].is_array() && !body["errors"].empty() &&
      body["errors"][0].is_object())
    return body["errors"][0].value("code", "");
  return {};
}

std::string ApiResult::deviceStatus() const {
  try {
    return body.at("errors").at(0).at("meta").value("device_status", "");
  } catch (const json::exception&) {
    return {};
  }
}

ApiResult Client::post(const std::string& path, const json& body) {
  HttpResponse r = http_.post(cfg_.baseUrl() + "/v1/client/desktop_mfa/" + path,
                              {{"X-Publishable-Key", cfg_.publishableKey}, {"Content-Type", "application/json"}},
                              body.dump());
  ApiResult out;
  out.status = r.status;
  if (!r.body.empty()) {
    json j = json::parse(r.body, nullptr, false);
    if (!j.is_discarded()) out.body = std::move(j);
  }
  return out;
}

ApiResult Client::signedCall(const std::string& path, const std::string& purpose,
                             const std::optional<std::string>& extra, json body) {
  ApiResult n = post("nonce", {{"device_id", cfg_.deviceId}});
  if (!n.ok() || !n.body.is_object() || !n.body.contains("nonce") || !n.body["nonce"].is_string()) {
    if (n.ok()) n.status = 502;  // a 2xx without a nonce is a broken server
    return n;
  }
  std::string nonce = n.body["nonce"];
  Bytes sig = key_.sign(toBytes(signedMessage(purpose, cfg_.instanceId, cfg_.deviceId, nonce, extra)));
  if (sig.size() != 64) { ApiResult e; e.status = 0; return e; }
  body["device_id"] = cfg_.deviceId;
  body["nonce"] = nonce;
  body["signature"] = b64uEncode(sig);
  return post(path, body);
}

ApiResult Client::enroll(const std::string& code, const std::string& pin, const std::string& hostname,
                         const std::string& platform, const std::string& agentVersion,
                         const std::optional<json>& sealPublicKey) {
  json jwk = key_.publicJwk();
  Bytes sig = key_.sign(toBytes(signedMessage("enroll", cfg_.instanceId, jwk.value("x", ""), code)));
  if (sig.size() != 64) return {};
  json body = {{"code", code}, {"public_key", jwk}, {"signature", b64uEncode(sig)}, {"hostname", hostname},
               {"platform", platform}, {"agent_version", agentVersion}};
  if (!pin.empty()) body["pin"] = pin;
  if (sealPublicKey) body["seal_public_key"] = *sealPublicKey;
  return post("enroll", body);
}

ApiResult Client::sync(const std::string& heldBundleId) {
  json body = json::object();
  if (!heldBundleId.empty()) body["held_bundle_id"] = heldBundleId;
  return signedCall("sync", "sync", heldBundleId.empty() ? "-" : heldBundleId, body);
}

ApiResult Client::setPin(const std::string& pin) {
  return signedCall("pin", "pin", b64uEncode(sha256(toBytes(pin))), {{"pin", pin}});
}

ApiResult Client::startChallenge(const std::string& factor) {
  return signedCall("challenges", "challenge", factor, {{"factor", factor}});
}

ApiResult Client::verify(const std::string& id, const std::optional<std::string>& code,
                         const std::optional<json>& assertion) {
  Bytes sig = key_.sign(toBytes(signedMessage("verify", cfg_.instanceId, cfg_.deviceId, id)));
  if (sig.size() != 64) return {};
  json body = {{"device_id", cfg_.deviceId}, {"signature", b64uEncode(sig)}};
  if (code) body["code"] = *code;
  if (assertion) body["assertion"] = *assertion;
  return post("challenges/" + id + "/verify", body);
}

ApiResult Client::report(const std::string& payload) {
  return signedCall("report", "report", b64uEncode(sha256(toBytes(payload))), {{"payload", payload}});
}

ApiResult Client::passkeyOptions(const std::string& proofChallengeId) {
  return signedCall("passkeys/options", "passkey_options", proofChallengeId, {{"proof_challenge_id", proofChallengeId}});
}

ApiResult Client::passkeyEnrol(const std::string& registrationId, const json& credential, const std::string& name,
                               const std::vector<std::string>& transports) {
  Bytes sig = key_.sign(toBytes(signedMessage("passkey_enrol", cfg_.instanceId, cfg_.deviceId, registrationId)));
  if (sig.size() != 64) return {};
  json body = {{"device_id", cfg_.deviceId}, {"signature", b64uEncode(sig)}, {"credential", credential}, {"transports", transports}};
  if (!name.empty()) body["name"] = name;
  return post("passkeys/" + registrationId + "/enrol", body);
}

// ---- SyncCache ----

json SyncCache::toJson() const {
  return {{"known", known}, {"required", required}, {"revoked", revoked}, {"offline_enabled", offlineEnabled},
          {"pin_required", pinRequired}, {"factors", factors}, {"synced_at", syncedAt}};
}

SyncCache SyncCache::fromJson(const json& j) {
  SyncCache c;
  if (!j.is_object()) return c;
  c.known = j.value("known", false);
  c.required = j.value("required", false);
  c.revoked = j.value("revoked", false);
  c.offlineEnabled = j.value("offline_enabled", false);
  c.pinRequired = j.value("pin_required", false);
  c.syncedAt = j.value("synced_at", static_cast<int64_t>(0));
  if (j.contains("factors") && j["factors"].is_array())
    for (const auto& f : j["factors"])
      if (f.is_string()) c.factors.push_back(f);
  return c;
}

SyncCache loadSyncCache(ISecretStore& s) {
  auto j = getJson(s, store::kSyncCache);
  return j ? SyncCache::fromJson(*j) : SyncCache{};
}

// ---- SyncService ----

void SyncService::flushEvents() {
  auto evs = vault_.events();
  if (evs.empty()) return;
  size_t n = std::min<size_t>(evs.size(), 200);
  json arr = json::array();
  for (size_t i = 0; i < n; i++) {
    json o = {{"at", evs[i].at}, {"outcome", evs[i].outcome}};
    if (!evs[i].bundleId.empty()) o["bundle_id"] = evs[i].bundleId;
    if (!evs[i].reason.empty()) o["reason"] = evs[i].reason;
    arr.push_back(o);
  }
  if (client_.report(arr.dump()).ok()) vault_.dropEvents(n);
}

SyncOutcome SyncService::run() {
  bundleRejected_ = false;
  auto held = vault_.heldBundle();
  ApiResult r = client_.sync(held ? held->bundleId : "");
  if (r.status == 403 && r.deviceStatus() == "revoked") {
    vault_.wipe();
    SyncCache c = loadSyncCache(store_);
    c.revoked = true;
    putJson(store_, store::kSyncCache, c.toJson());
    return SyncOutcome::Revoked;
  }
  if (r.unreachable()) return SyncOutcome::Unreachable;
  if (!r.ok() || !r.body.is_object() || !r.body.contains("required") || !r.body["required"].is_boolean())
    return SyncOutcome::Rejected;

  SyncCache c;
  c.known = true;
  c.required = r.body["required"];
  c.syncedAt = clock_.nowMs();
  if (r.body.contains("allowed_factors") && r.body["allowed_factors"].is_array())
    for (const auto& f : r.body["allowed_factors"])
      if (f.is_string()) c.factors.push_back(f);
  const json off = r.body.contains("offline") && r.body["offline"].is_object() ? r.body["offline"] : json::object();
  c.offlineEnabled = off.value("enabled", false);
  c.pinRequired = off.value("pin_required", false);
  putJson(store_, store::kSyncCache, c.toJson());

  if (!off.value("keep_cache", true) || !c.offlineEnabled) vault_.wipe();
  else if (off.contains("bundle") && off["bundle"].is_object()) {
    auto b = Bundle::fromJson(off["bundle"]);
    if (!b || !vault_.storeBundle(*b)) bundleRejected_ = true;
  }
  vault_.noteTime();
  flushEvents();
  return SyncOutcome::Ok;
}

// ---- enrolment ----

EnrollResult enrollDevice(Config& cfg, IDeviceKey& key, IHttpClient& http, ISecretStore& store, const std::string& code,
                          const std::string& pin, const std::string& hostname, const std::string& platform,
                          const std::string& agentVersion, ISealKey* sealKey) {
  EnrollResult out;
  Client c(cfg, key, http);
  std::optional<json> sealPub;
  if (sealKey) sealPub = sealKey->publicJwk();
  ApiResult r = c.enroll(code, pin, hostname, platform, agentVersion, sealPub);
  if (r.status == 0) { out.error = "server unreachable"; return out; }
  if (!r.ok()) { out.error = r.errorCode().empty() ? "enrolment refused (" + std::to_string(r.status) + ")" : r.errorCode(); return out; }
  try {
    std::string id = r.body.at("device").at("id");
    std::string mk = r.body.at("bundle_mac_key");
    if (id.empty() || !b64uDecode(mk) ) { out.error = "malformed enrolment response"; return out; }
    if (!putString(store, store::kMacKey, mk)) { out.error = "could not store the bundle key"; return out; }
    cfg.deviceId = id;
    cfg.enrolled = true;
    out.offlineOtpUri = r.body.value("offline_otp_uri", "");
    out.ok = true;
  } catch (const json::exception&) {
    out.error = "malformed enrolment response";
  }
  return out;
}

}  // namespace atlas
