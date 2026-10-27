#include <gtest/gtest.h>

#include "fixture.hpp"

using namespace atlas;
using namespace t;

namespace {

Config cfg(bool failOpen = false) {
  Config c;
  c.instanceUrl = "https://auth.example.com";
  c.publishableKey = "pk_test_1";
  c.instanceId = "ins_TESTVECTOR";
  c.deviceId = "ddv_TESTVECTOR";
  c.deviceKeyId = "key";
  c.enrolled = true;
  c.failOpenWhenNeverSynced = failOpen;
  return c;
}

// A tiny stand-in for the Atlas server. It checks every signature against the device's public key
// and the exact signed-message format, so a wrong message shape fails here.
struct Server {
  json pub = vectors()["device_public_jwk"];
  int nonceN = 0;
  std::string lastNonce;
  bool required = true;
  json factors = json::array({"push", "totp"});
  bool offlineEnabled = true, keepCache = true, withBundle = true, revoked = false;
  bool tamperBundleMac = false;
  std::string pushStatus = "pending";   // what verify returns for a push challenge
  std::string rightCode = "123456";
  int wrongAnswers = 0;
  std::string lastHeld;
  std::string reportPayload;
  std::set<std::string> usedNonces;
  std::vector<std::string> badSignatures;

  bool sigOk(const json& b, const std::string& purpose, const std::string& nonce, const std::optional<std::string>& extra) {
    auto sig = b64uDecode(b.value("signature", ""));
    std::string m = signedMessage(purpose, "ins_TESTVECTOR", "ddv_TESTVECTOR", nonce, extra);
    bool ok = sig && ecdsaVerifyP1363(pub, toBytes(m), *sig);
    if (!ok) badSignatures.push_back(purpose);
    return ok;
  }
  static HttpResponse err(int status, const char* code, json meta = nullptr) {
    json e = {{"code", code}, {"message", "x"}};
    if (!meta.is_null()) e["meta"] = meta;
    return reply(status, {{"errors", json::array({e})}});
  }

  HttpResponse handle(const std::string& path, const json& b) {
    if (path == "nonce") {
      lastNonce = "n" + std::to_string(++nonceN);
      return reply(201, {{"nonce", lastNonce}});
    }
    if (path.rfind("challenges/", 0) == 0) {
      std::string id = path.substr(11, path.size() - 11 - 7);
      if (!sigOk(b, "verify", id, std::nullopt)) return err(401, "unauthorized");
      if (b.contains("code")) {
        if (b["code"] == rightCode) return reply(200, {{"status", "verified"}});
        if (++wrongAnswers >= 5) return err(429, "too_many_attempts");
        return err(422, "verification_failed");
      }
      return reply(200, {{"status", pushStatus}});
    }
    // single-use nonce, bound to this call
    auto n = b.value("nonce", "");
    if (usedNonces.count(n)) return err(401, "unauthorized");
    usedNonces.insert(n);
    if (path == "sync") {
      lastHeld = b.value("held_bundle_id", "");
      if (!sigOk(b, "sync", n, lastHeld.empty() ? "-" : lastHeld)) return err(401, "unauthorized");
      if (revoked) return err(403, "forbidden", {{"device_status", "revoked"}});
      json off = {{"enabled", offlineEnabled}, {"grace_hours", 72}, {"pin_required", true}, {"pin_set", true},
                  {"keep_cache", keepCache}, {"bundle_valid", false}};
      if (withBundle && lastHeld.empty()) {
        Bundle bb = vectorBundle();
        if (tamperBundleMac) bb.mac = "AAAA";
        off["bundle"] = bb.toJson();
      }
      return reply(200, {{"status", "active"}, {"required", required}, {"allowed_factors", factors}, {"offline", off},
                         {"server_time", 1800000000000}});
    }
    if (path == "challenges") {
      std::string f = b.value("factor", "");
      if (!sigOk(b, "challenge", n, f)) return err(401, "unauthorized");
      json r = {{"id", "chl_" + f}, {"factor", f}, {"expires_at", 1}};
      if (f == "push") r["number_match"] = "47";
      if (f == "passkey") r["passkey_options"] = {{"challenge", "abc"}};
      return reply(201, r);
    }
    if (path == "report") {
      reportPayload = b.value("payload", "");
      if (!sigOk(b, "report", n, b64uEncode(sha256(toBytes(reportPayload))))) return err(401, "unauthorized");
      return reply(200, {{"accepted", 1}});
    }
    return err(404, "not_found");
  }
};

struct Rig {
  Config config;
  Server server;
  MockHttp http;
  MemorySecretStore store;
  TestClock clock;
  std::unique_ptr<SoftwareDeviceKey> key = vectorKey();
  std::unique_ptr<Client> client;
  std::unique_ptr<OfflineVault> vault;
  std::unique_ptr<SyncService> sync;
  std::unique_ptr<LoginGate> gate;

  explicit Rig(bool failOpen = false, bool withMacKey = true) : config(cfg(failOpen)) {
    http.handler = [this](const std::string& p, const json& b) { return server.handle(p, b); };
    if (withMacKey) putString(store, "mac_key", vectors()["mac_key_b64u"]);
    client = std::make_unique<Client>(config, *key, http);
    vault = std::make_unique<OfflineVault>(store, clock, *key, "ddv_TESTVECTOR");
    sync = std::make_unique<SyncService>(config, *client, *vault, store, clock);
    gate = std::make_unique<LoginGate>(config, *client, *sync, *vault, store);
  }
};

}  // namespace

// ---- client ----

TEST(Client, SendsPublishableKeyAndSignedSync) {
  Rig r;
  EXPECT_EQ(r.sync->run(), SyncOutcome::Ok);
  EXPECT_TRUE(r.server.badSignatures.empty());
  ASSERT_GE(r.http.log.size(), 2u);
  bool hasKey = false;
  for (auto& h : r.http.log[0].headers) hasKey |= h.first == "X-Publishable-Key" && h.second == "pk_test_1";
  EXPECT_TRUE(hasKey);
  EXPECT_EQ(r.http.log[0].path, "nonce");
  EXPECT_EQ(r.http.log[0].body["device_id"], "ddv_TESTVECTOR");
}

TEST(Client, EnrollSignsCodeWithJwkX) {
  Rig r;
  r.config.enrolled = false;
  r.config.deviceId.clear();
  bool signedOk = false;
  r.http.handler = [&](const std::string& p, const json& b) {
    EXPECT_EQ(p, "enroll");
    std::string m = signedMessage("enroll", "ins_TESTVECTOR", vectors()["device_public_jwk"]["x"], "CODE-1");
    signedOk = ecdsaVerifyP1363(b["public_key"], toBytes(m), *b64uDecode(b["signature"]));
    EXPECT_EQ(b["platform"], "windows");
    EXPECT_EQ(b["pin"], "24681357");
    return reply(201, {{"device", {{"id", "ddv_NEW"}}}, {"bundle_mac_key", vectors()["mac_key_b64u"]},
                       {"offline_otp_uri", "otpauth://totp/x"}});
  };
  MemorySecretStore st;
  auto res = enrollDevice(r.config, *r.key, r.http, st, "CODE-1", "24681357", "host", "windows", "0.1.0");
  EXPECT_TRUE(signedOk);
  ASSERT_TRUE(res.ok) << res.error;
  EXPECT_EQ(r.config.deviceId, "ddv_NEW");
  EXPECT_TRUE(r.config.enrolled);
  EXPECT_EQ(*getString(st, "mac_key"), vectors()["mac_key_b64u"].get<std::string>());
  EXPECT_EQ(res.offlineOtpUri, "otpauth://totp/x");
}

TEST(Client, EnrollRefusalsDoNotPersist) {
  Rig r;
  r.config.enrolled = false;
  MemorySecretStore st;
  r.http.handler = [](const std::string&, const json&) { return Server::err(401, "unauthorized"); };
  auto res = enrollDevice(r.config, *r.key, r.http, st, "bad", "", "h", "windows", "v");
  EXPECT_FALSE(res.ok);
  EXPECT_FALSE(r.config.enrolled);
  EXPECT_FALSE(st.get("mac_key"));
  r.http.down = true;
  EXPECT_EQ(enrollDevice(r.config, *r.key, r.http, st, "c", "", "h", "windows", "v").error, "server unreachable");
}

// ---- sync ----

TEST(Sync, StoresBundleCachesStateAndHoldsBundleId) {
  Rig r;
  EXPECT_EQ(r.sync->run(), SyncOutcome::Ok);
  ASSERT_TRUE(r.vault->heldBundle());
  SyncCache c = loadSyncCache(r.store);
  EXPECT_TRUE(c.known);
  EXPECT_TRUE(c.required);
  EXPECT_EQ(c.factors, (std::vector<std::string>{"push", "totp"}));
  EXPECT_EQ(r.sync->run(), SyncOutcome::Ok);
  EXPECT_EQ(r.server.lastHeld, "ddb_TESTVECTOR");  // second sync advertises the bundle it holds
}

TEST(Sync, TamperedBundleMacIsNotStored) {
  Rig r;
  r.server.tamperBundleMac = true;
  EXPECT_EQ(r.sync->run(), SyncOutcome::Ok);
  EXPECT_TRUE(r.sync->lastBundleRejected());
  EXPECT_FALSE(r.vault->heldBundle());
}

TEST(Sync, BundleWithoutMacKeyIsNotStored) {
  Rig r(false, false);
  r.sync->run();
  EXPECT_FALSE(r.vault->heldBundle());
}

TEST(Sync, KeepCacheFalseDeletesBundle) {
  Rig r;
  r.sync->run();
  ASSERT_TRUE(r.vault->heldBundle());
  r.server.keepCache = false;
  r.sync->run();
  EXPECT_FALSE(r.vault->heldBundle());
}

TEST(Sync, RevokedWipesCacheAndMarksDevice) {
  Rig r;
  r.sync->run();
  r.server.revoked = true;
  EXPECT_EQ(r.sync->run(), SyncOutcome::Revoked);
  EXPECT_FALSE(r.vault->heldBundle());
  EXPECT_TRUE(loadSyncCache(r.store).revoked);
}

TEST(Sync, UnreachableAndServerErrors) {
  Rig r;
  r.http.down = true;
  EXPECT_EQ(r.sync->run(), SyncOutcome::Unreachable);
  r.http.down = false;
  r.http.handler = [](const std::string&, const json&) { return HttpResponse{503, "oops"}; };
  EXPECT_EQ(r.sync->run(), SyncOutcome::Unreachable);
  r.http.handler = [](const std::string&, const json&) { return Server::err(401, "unauthorized"); };
  EXPECT_EQ(r.sync->run(), SyncOutcome::Rejected);
  EXPECT_FALSE(loadSyncCache(r.store).known);  // a failed sync never writes the cache
}

TEST(Sync, QueuedOfflineEventsAreReportedThenDropped) {
  Rig r;
  r.sync->run();
  r.vault->unlock("00000000", "000000");
  r.vault->unlock(vectors()["pin"]["value"], "877905");
  ASSERT_EQ(r.vault->events().size(), 2u);
  r.sync->run();
  json sent = json::parse(r.server.reportPayload);
  ASSERT_EQ(sent.size(), 2u);
  EXPECT_EQ(sent[0]["outcome"], "failure");
  EXPECT_EQ(sent[1]["outcome"], "success");
  EXPECT_EQ(sent[1]["bundle_id"], "ddb_TESTVECTOR");
  EXPECT_TRUE(r.vault->events().empty());
  EXPECT_TRUE(r.server.badSignatures.empty());
}

TEST(Sync, EventsKeptWhenReportFails) {
  Rig r;
  r.sync->run();
  r.vault->unlock("00000000", "000000");
  r.http.handler = [&](const std::string& p, const json& b) {
    if (p == "report") return HttpResponse{500, ""};
    return r.server.handle(p, b);
  };
  r.sync->run();
  EXPECT_EQ(r.vault->events().size(), 1u);
}

// ---- gate ----

TEST(Gate, NotRequiredLetsPasswordThrough) {
  Rig r;
  r.server.required = false;
  EXPECT_EQ(r.gate->begin().kind, GateDecision::Kind::NotRequired);
  EXPECT_TRUE(r.gate->satisfied());
}

TEST(Gate, PushHappyPathShowsNumberMatch) {
  Rig r;
  auto d = r.gate->begin();
  ASSERT_EQ(d.kind, GateDecision::Kind::Required);
  EXPECT_TRUE(d.online);
  EXPECT_FALSE(r.gate->satisfied());
  auto s = r.gate->startPush();
  EXPECT_EQ(s.step, Step::Pending);
  EXPECT_EQ(s.detail, "47");
  EXPECT_EQ(r.gate->pollPush().step, Step::Pending);
  EXPECT_FALSE(r.gate->satisfied());
  r.server.pushStatus = "verified";
  EXPECT_EQ(r.gate->pollPush().step, Step::Verified);
  EXPECT_TRUE(r.gate->satisfied());
  EXPECT_TRUE(r.server.badSignatures.empty());
  r.gate->reset();
  EXPECT_FALSE(r.gate->satisfied());
}

TEST(Gate, PushDeniedOnPhoneFails) {
  Rig r;
  r.gate->begin();
  r.gate->startPush();
  r.server.pushStatus = "failed";
  EXPECT_EQ(r.gate->pollPush().step, Step::Failed);
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->pollPush().step, Step::Failed);  // challenge is gone, never "verified"
}

TEST(Gate, TotpWrongThenRight) {
  Rig r;
  r.gate->begin();
  EXPECT_EQ(r.gate->submitCode("000000").step, Step::WrongCode);
  EXPECT_EQ(r.gate->submitCode("12ab56").step, Step::WrongCode);  // malformed: never sent
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->submitCode("123456").step, Step::Verified);
  EXPECT_TRUE(r.gate->satisfied());
  EXPECT_EQ(r.http.count("challenges"), 1u);  // one challenge reused for the retry
}

TEST(Gate, TotpFiveWrongEndsChallenge) {
  Rig r;
  r.gate->begin();
  Step last = Step::Pending;
  for (int i = 0; i < 5; i++) last = r.gate->submitCode("000000").step;
  EXPECT_EQ(last, Step::Failed);
  EXPECT_FALSE(r.gate->satisfied());
}

TEST(Gate, PasskeyUnsupportedUnlessHandlerInjected) {
  Rig r;
  r.server.factors = json::array({"passkey"});
  r.gate->begin();
  auto s = r.gate->submitPasskey();
  EXPECT_EQ(s.step, Step::Unsupported);
  EXPECT_EQ(s.detail, "unsupported_in_this_build");
  EXPECT_FALSE(r.gate->satisfied());

  r.gate->setPasskeyHandler([](const json& o) -> std::optional<json> {
    EXPECT_EQ(o["challenge"], "abc");
    return json{{"challenge", "abc"}, {"credential_id", "c"}, {"authenticator_data", "a"}, {"client_data_json", "d"}, {"signature", "s"}};
  });
  r.server.pushStatus = "verified";
  EXPECT_EQ(r.gate->submitPasskey().step, Step::Verified);
}

TEST(Gate, RevokedDevicePreviouslyRequiredIsDenied) {
  Rig r;
  r.gate->begin();  // caches required + bundle
  r.server.revoked = true;
  auto d = r.gate->begin();
  EXPECT_EQ(d.kind, GateDecision::Kind::Denied);
  EXPECT_EQ(d.reason, "revoked");
  EXPECT_FALSE(r.vault->heldBundle());
  EXPECT_FALSE(r.gate->satisfied());
  // and it stays denied when the network later drops: the cache says revoked
  r.http.down = true;
  EXPECT_EQ(r.gate->begin().kind, GateDecision::Kind::Denied);
}

TEST(Gate, UnreachableFallsBackToOfflineUnlock) {
  Rig r;
  r.gate->begin();  // online: caches state and bundle
  r.http.down = true;
  auto d = r.gate->begin();
  ASSERT_EQ(d.kind, GateDecision::Kind::Required);
  EXPECT_FALSE(d.online);
  EXPECT_TRUE(d.offlineAvailable);
  EXPECT_TRUE(d.offlinePinRequired);
  EXPECT_TRUE(d.factors.empty());
  EXPECT_EQ(r.gate->startPush().step, Step::Unsupported);
  EXPECT_EQ(r.gate->submitOffline("00000000", "877905").step, Step::WrongCode);
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->submitOffline(vectors()["pin"]["value"], "877905").step, Step::Verified);
  EXPECT_TRUE(r.gate->satisfied());
}

TEST(Gate, OfflineLockoutThroughGate) {
  Rig r;
  r.gate->begin();
  r.http.down = true;
  r.gate->begin();
  for (int i = 0; i < 5; i++) r.gate->submitOffline(vectors()["pin"]["value"], "000000");
  EXPECT_EQ(r.gate->submitOffline(vectors()["pin"]["value"], "877905").step, Step::Locked);
  EXPECT_FALSE(r.gate->satisfied());
}

TEST(Gate, UnreachableWithExpiredBundleIsDenied) {
  Rig r;
  r.gate->begin();
  r.http.down = true;
  r.clock.now = 1800259200000 + 1000;
  auto d = r.gate->begin();
  EXPECT_EQ(d.kind, GateDecision::Kind::Denied);
  EXPECT_EQ(d.reason, "offline_expired");
}

TEST(Gate, UnreachableWithClockRolledBackIsDenied) {
  Rig r;
  r.gate->begin();
  r.http.down = true;
  r.clock.now += 2 * 24 * 3600 * 1000LL;
  r.gate->begin();
  r.vault->noteTime();
  r.clock.now -= 24 * 3600 * 1000LL;
  auto d = r.gate->begin();
  EXPECT_EQ(d.kind, GateDecision::Kind::Denied);
  EXPECT_EQ(d.reason, "clock");
}

TEST(Gate, RequiredButNoBundleAndOfflineIsDenied) {
  Rig r;
  r.server.withBundle = false;
  r.gate->begin();
  r.http.down = true;
  auto d = r.gate->begin();
  EXPECT_EQ(d.kind, GateDecision::Kind::Denied);
  EXPECT_EQ(d.reason, "offline_unavailable");
}

TEST(Gate, OfflineDisabledByPolicyIsDenied) {
  Rig r;
  r.server.offlineEnabled = false;
  r.gate->begin();
  r.http.down = true;
  EXPECT_EQ(r.gate->begin().reason, "offline_unavailable");
}

TEST(Gate, NeverSyncedFailsClosedByDefault) {
  Rig r;
  r.http.down = true;
  auto d = r.gate->begin();
  EXPECT_EQ(d.kind, GateDecision::Kind::Denied);
  EXPECT_EQ(d.reason, "never_synced");
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->submitOffline("1", "123456").step, Step::Unsupported);
}

TEST(Gate, NeverSyncedFailOpenOnlyWhenConfigured) {
  Rig r(true);
  r.http.down = true;
  EXPECT_EQ(r.gate->begin().kind, GateDecision::Kind::NotRequired);
  EXPECT_TRUE(r.gate->satisfied());
}

TEST(Gate, CachedNotRequiredAllowsWhileOffline) {
  Rig r;
  r.server.required = false;
  r.gate->begin();
  r.http.down = true;
  EXPECT_EQ(r.gate->begin().kind, GateDecision::Kind::NotRequired);
}

TEST(Gate, RequiredStaysRequiredOfflineEvenIfServerStopsAnswering) {
  Rig r;
  r.gate->begin();
  r.http.handler = [](const std::string&, const json&) { return HttpResponse{502, "bad gateway"}; };
  auto d = r.gate->begin();
  EXPECT_EQ(d.kind, GateDecision::Kind::Required);  // never silently drops to password-only
  EXPECT_FALSE(r.gate->satisfied());
}

TEST(Gate, UnreachableDuringChallengeIsNotVerified) {
  Rig r;
  r.gate->begin();
  r.gate->startPush();
  r.http.down = true;
  EXPECT_EQ(r.gate->pollPush().step, Step::Unreachable);
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->submitCode("123456").step, Step::Unreachable);
}

TEST(Gate, UnenrolledIsDeniedByTheCoreCallerDecidesPassthrough) {
  Rig r;
  r.config.enrolled = false;
  EXPECT_EQ(r.gate->begin().reason, "not_enrolled");
}
