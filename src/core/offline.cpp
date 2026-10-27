#include "atlas/offline.hpp"

#include "atlas/client.hpp"  // store::kMacKey

#include <algorithm>

namespace atlas {

namespace {
const char* kBundleKey = "bundle";
const char* kStateKey = "offline_state";
}  // namespace

json Bundle::toJson() const {
  return {{"bundle_id", bundleId}, {"generation", generation}, {"issued_at", issuedAt},
          {"expires_at", expiresAt}, {"sealed", sealed}, {"mac", mac}};
}

std::optional<Bundle> Bundle::fromJson(const json& j) {
  if (!j.is_object()) return std::nullopt;
  auto s = [&](const char* k) { return j.contains(k) && j[k].is_string(); };
  auto n = [&](const char* k) { return j.contains(k) && j[k].is_number_integer(); };
  if (!s("bundle_id") || !s("sealed") || !s("mac") || !n("generation") || !n("expires_at")) return std::nullopt;
  Bundle b;
  b.bundleId = j["bundle_id"];
  b.sealed = j["sealed"];
  b.mac = j["mac"];
  b.generation = j["generation"];
  b.expiresAt = j["expires_at"];
  b.issuedAt = n("issued_at") ? j["issued_at"].get<int64_t>() : 0;
  return b;
}

std::string bundleMac(const Bytes& macKey, const std::string& deviceId, const Bundle& b) {
  std::string msg = "atlas-desktop-bundle:v1:" + deviceId + ":" + b.bundleId + ":" + std::to_string(b.generation) +
                    ":" + std::to_string(b.expiresAt) + ":" + b.sealed;
  return b64uEncode(hmac("SHA256", macKey, toBytes(msg)));
}

bool bundleMacOk(const Bytes& macKey, const std::string& deviceId, const Bundle& b) {
  if (macKey.empty()) return false;
  return ctEqual(bundleMac(macKey, deviceId, b), b.mac);
}

std::optional<BundlePlain> openBundle(ISealKey& key, const std::string& sealed) {
  auto rawOpt = b64uDecode(sealed);
  // 1 version + 65 point + 12 iv + 16 tag minimum
  if (!rawOpt || rawOpt->size() < 1 + 65 + 12 + 16 || (*rawOpt)[0] != 0x01 || (*rawOpt)[1] != 0x04) return std::nullopt;
  const Bytes& raw = *rawOpt;
  Bytes eph(raw.begin() + 1, raw.begin() + 66), iv(raw.begin() + 66, raw.begin() + 78),
      ct(raw.begin() + 78, raw.end() - 16), tag(raw.end() - 16, raw.end());
  Bytes secret = key.ecdh(eph);
  if (secret.size() != 32) return std::nullopt;
  Bytes k = hkdfSha256(secret, eph, toBytes("atlas-desktop-offline-bundle-v1"), 32);
  Bytes plain;
  if (k.size() != 32 || !aes256GcmDecrypt(k, iv, ct, tag, plain)) return std::nullopt;
  json j = json::parse(toString(plain), nullptr, false);
  if (j.is_discarded() || !j.is_object() || j.value("v", 0) != 1) return std::nullopt;
  try {
    BundlePlain p;
    p.bundleId = j.at("bundle_id");
    p.deviceId = j.at("device_id");
    p.userId = j.value("user_id", "");
    p.generation = j.at("generation");
    p.issuedAt = j.at("issued_at");
    p.expiresAt = j.at("expires_at");
    p.pinRequired = j.at("pin_required");
    if (j.contains("pin") && j["pin"].is_object()) {
      const json& pj = j["pin"];
      if (pj.value("alg", "") != "scrypt") return std::nullopt;
      PinVerifier v;
      v.N = pj.at("N"); v.r = pj.at("r"); v.p = pj.at("p");
      v.salt = pj.at("salt"); v.hash = pj.at("hash");
      p.pin = v;
    }
    const json& t = j.at("totp");
    p.totp.secret = t.at("secret");
    p.totp.digits = t.value("digits", 6);
    p.totp.period = t.value("period", 30);
    p.totp.algorithm = t.value("algorithm", "SHA1");
    if (p.totp.algorithm != "SHA1" || p.totp.digits != 6 || p.totp.period != 30) return std::nullopt;
    if (p.pinRequired && !p.pin) return std::nullopt;
    return p;
  } catch (const json::exception&) {
    return std::nullopt;
  }
}

bool verifyPin(const std::string& pin, const PinVerifier& v) {
  auto salt = b64uDecode(v.salt), hash = b64uDecode(v.hash);
  if (!salt || !hash || hash->size() != 32) return false;
  auto d = scryptDerive(pin, *salt, v.N, v.r, v.p, 32);
  return d && ctEqual(*d, *hash);
}

std::string totpCode(const std::string& base32Secret, int64_t unixSeconds, int digits, int period) {
  auto key = base32Decode(base32Secret);
  if (!key || key->empty() || period <= 0 || unixSeconds < 0) return {};
  uint64_t counter = static_cast<uint64_t>(unixSeconds / period);
  Bytes msg(8);
  for (int i = 7; i >= 0; i--) { msg[i] = counter & 0xff; counter >>= 8; }
  Bytes h = hmac("SHA1", *key, msg);
  if (h.size() != 20) return {};
  size_t o = h[19] & 0x0f;
  uint32_t bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  uint32_t mod = 1;
  for (int i = 0; i < digits; i++) mod *= 10;
  std::string s = std::to_string(bin % mod);
  return std::string(static_cast<size_t>(digits) - std::min<size_t>(s.size(), static_cast<size_t>(digits)), '0') + s;
}

std::optional<int64_t> totpMatch(const std::string& secret, const std::string& code, int64_t unixSeconds,
                                 int64_t lastStep) {
  if (code.size() != 6) return std::nullopt;
  int64_t cur = unixSeconds / 30;
  std::optional<int64_t> hit;
  // Check all three steps without early exit so timing does not reveal which one matched.
  for (int64_t step = cur - 1; step <= cur + 1; step++) {
    std::string expect = totpCode(secret, step * 30);
    if (!expect.empty() && ctEqual(expect, code) && step > lastStep && !hit) hit = step;
  }
  return hit;
}

// ---- OfflineVault ----

OfflineVault::OfflineVault(ISecretStore& store, IClock& clock, ISealKey& key, std::string deviceId)
    : store_(store), clock_(clock), key_(key), deviceId_(std::move(deviceId)) {}

OfflineVault::State OfflineVault::load() {
  State s;
  auto j = getJson(store_, kStateKey);
  if (!j || !j->is_object()) return s;
  s.fails = j->value("fails", 0);
  s.lockUntil = j->value("lock_until", static_cast<int64_t>(0));
  s.lastStep = j->value("last_step", static_cast<int64_t>(-1));
  s.highWater = j->value("high_water", static_cast<int64_t>(0));
  if (j->contains("events") && (*j)["events"].is_array())
    for (const auto& e : (*j)["events"]) {
      OfflineEvent ev;
      ev.at = e.value("at", static_cast<int64_t>(0));
      ev.outcome = e.value("outcome", "failure");
      ev.bundleId = e.value("bundle_id", "");
      ev.reason = e.value("reason", "");
      s.events.push_back(ev);
    }
  return s;
}

void OfflineVault::save(const State& s) {
  json ev = json::array();
  size_t start = s.events.size() > kMaxQueuedEvents ? s.events.size() - kMaxQueuedEvents : 0;
  for (size_t i = start; i < s.events.size(); i++) {
    const auto& e = s.events[i];
    json o = {{"at", e.at}, {"outcome", e.outcome}};
    if (!e.bundleId.empty()) o["bundle_id"] = e.bundleId;
    if (!e.reason.empty()) o["reason"] = e.reason;
    ev.push_back(o);
  }
  putJson(store_, kStateKey,
          {{"fails", s.fails}, {"lock_until", s.lockUntil}, {"last_step", s.lastStep}, {"high_water", s.highWater}, {"events", ev}});
}

bool OfflineVault::storeBundle(const Bundle& b) {
  auto mk = getString(store_, store::kMacKey);
  auto key = mk ? b64uDecode(*mk) : std::nullopt;
  if (!key || !bundleMacOk(*key, deviceId_, b)) return false;
  return putJson(store_, kBundleKey, b.toJson());
}

std::optional<Bundle> OfflineVault::heldBundle() {
  auto j = getJson(store_, kBundleKey);
  return j ? Bundle::fromJson(*j) : std::nullopt;
}

void OfflineVault::wipe() { store_.remove(kBundleKey); }

void OfflineVault::noteTime() {
  State s = load();
  int64_t now = clock_.nowMs();
  if (now > s.highWater) { s.highWater = now; save(s); }
}

// Everything that must hold before a code is even considered. Does not touch counters.
OfflineResult OfflineVault::check(State& s, BundlePlain& plain, int64_t now) {
  auto b = heldBundle();
  if (!b) return OfflineResult::NoBundle;
  auto mk = getString(store_, store::kMacKey);
  auto key = mk ? b64uDecode(*mk) : std::nullopt;
  if (!key || !bundleMacOk(*key, deviceId_, *b)) return OfflineResult::BundleInvalid;
  auto p = openBundle(key_, b->sealed);
  if (!p || p->deviceId != deviceId_ || p->bundleId != b->bundleId || p->generation != b->generation ||
      p->expiresAt != b->expiresAt)
    return OfflineResult::BundleInvalid;
  if (now + kClockSlackMs < s.highWater || now + kClockSlackMs < p->issuedAt) return OfflineResult::ClockRollback;
  if (now >= p->expiresAt) return OfflineResult::Expired;
  plain = *p;
  return OfflineResult::Ok;
}

OfflineResult OfflineVault::status() {
  State s = load();
  BundlePlain p;
  return check(s, p, clock_.nowMs());
}

bool OfflineVault::pinRequired() {
  auto b = heldBundle();
  if (!b) return false;
  auto p = openBundle(key_, b->sealed);
  return p && p->pinRequired;
}

OfflineResult OfflineVault::unlock(const std::string& pin, const std::string& code) {
  State s = load();
  int64_t now = clock_.nowMs();
  auto bundle = heldBundle();
  std::string bid = bundle ? bundle->bundleId : "";
  auto log = [&](bool ok, const char* reason) {
    s.events.push_back({now, ok ? "success" : "failure", bid, reason});
  };
  if (now < s.lockUntil) {
    log(false, "locked");
    save(s);
    return OfflineResult::Locked;
  }
  BundlePlain plain;
  OfflineResult pre = check(s, plain, now);
  if (pre != OfflineResult::Ok) {
    // A broken bundle or a clock problem is not a guess by the user: no strike, no high-water change on rollback.
    log(false, pre == OfflineResult::ClockRollback ? "clock" : pre == OfflineResult::Expired ? "expired" : "bundle");
    save(s);
    return pre;
  }
  bool pinOk = !plain.pinRequired || (plain.pin && verifyPin(pin, *plain.pin));
  auto step = totpMatch(plain.totp.secret, code, now / 1000, s.lastStep);
  if (!pinOk || !step) {
    s.fails++;
    if (s.fails >= kMaxAttempts) {
      s.lockUntil = now + kLockMs;
      s.fails = 0;
    }
    log(false, !pinOk ? "pin" : "code");
    if (now > s.highWater) s.highWater = now;
    save(s);
    return OfflineResult::WrongCredentials;
  }
  s.fails = 0;
  s.lastStep = *step;
  if (now > s.highWater) s.highWater = now;
  log(true, "");
  save(s);
  return OfflineResult::Ok;
}

std::vector<OfflineEvent> OfflineVault::events() { return load().events; }

void OfflineVault::dropEvents(size_t n) {
  State s = load();
  s.events.erase(s.events.begin(), s.events.begin() + static_cast<std::ptrdiff_t>(std::min(n, s.events.size())));
  save(s);
}

}  // namespace atlas
