#include <gtest/gtest.h>

#include "fixture.hpp"
#include "atlas/cli.hpp"

#include <deque>

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
  json passkeyOptions = {{"challenge", "abc"}};
  bool rejectAssertion = false;
  json lastAssertion, lastCredential;
  std::string lastRegistration;

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
      if (b.contains("assertion")) {
        lastAssertion = b["assertion"];
        if (rejectAssertion) return err(422, "verification_failed");
        return reply(200, {{"status", pushStatus}});
      }
      if (b.contains("code")) {
        if (b["code"] == rightCode) return reply(200, {{"status", "verified"}});
        if (++wrongAnswers >= 5) return err(429, "too_many_attempts");
        return err(422, "verification_failed");
      }
      return reply(200, {{"status", pushStatus}});
    }
    if (path.rfind("passkeys/", 0) == 0 && path != "passkeys/options") {  // the registration id plays the nonce
      std::string id = path.substr(9, path.size() - 9 - 6);
      if (!sigOk(b, "passkey_enrol", id, std::nullopt)) return err(401, "unauthorized");
      lastRegistration = id;
      lastCredential = b["credential"];
      return reply(201, {{"object", "desktop_passkey"}, {"id", "ddp_1"}, {"name", b.value("name", "")}});
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
    if (path == "passkeys/options") {
      std::string proof = b.value("proof_challenge_id", "");
      if (!sigOk(b, "passkey_options", n, proof)) return err(401, "unauthorized");
      if (proof != "chl_totp") return err(403, "verification_failed");
      return reply(201, {{"registration_id", proof},
                         {"passkey_options", {{"challenge", "QUJDREVGR0hJSktMTU5PUA"}, {"rp", {{"id", "auth.example.com"}, {"name", "Atlas"}}},
                                              {"origin", "https://auth.example.com"}, {"user", {{"id", "dXNyXzE"}, {"name", "u"}, {"displayName", "U"}}},
                                              {"pubKeyCredParams", json::array({{{"type", "public-key"}, {"alg", -7}}})},
                                              {"excludeCredentials", json::array()},
                                              {"authenticatorSelection", {{"userVerification", "required"}}}}}});
    }
    if (path == "challenges") {
      std::string f = b.value("factor", "");
      if (!sigOk(b, "challenge", n, f)) return err(401, "unauthorized");
      json r = {{"id", "chl_" + f}, {"factor", f}, {"expires_at", 1}};
      if (f == "push") r["number_match"] = "47";
      if (f == "passkey") r["passkey_options"] = passkeyOptions;
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
  // Separate keys: signing is freshly generated; offline bundles are sealed to the vector key (the seal key).
  std::unique_ptr<SoftwareDeviceKey> key = SoftwareDeviceKey::generate();
  std::unique_ptr<SoftwareDeviceKey> seal = vectorKey();
  std::unique_ptr<Client> client;
  std::unique_ptr<OfflineVault> vault;
  std::unique_ptr<SyncService> sync;
  std::unique_ptr<LoginGate> gate;

  explicit Rig(bool failOpen = false, bool withMacKey = true) : config(cfg(failOpen)) {
    server.pub = key->publicJwk();
    http.handler = [this](const std::string& p, const json& b) { return server.handle(p, b); };
    if (withMacKey) putString(store, "mac_key", vectors()["mac_key_b64u"]);
    client = std::make_unique<Client>(config, *key, http);
    vault = std::make_unique<OfflineVault>(store, clock, *seal, "ddv_TESTVECTOR");
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
    std::string m = signedMessage("enroll", "ins_TESTVECTOR", r.key->publicJwk()["x"], "CODE-1");
    signedOk = ecdsaVerifyP1363(b["public_key"], toBytes(m), *b64uDecode(b["signature"]));
    EXPECT_EQ(b["platform"], "windows");
    EXPECT_EQ(b["seal_public_key"], r.seal->publicJwk());
    EXPECT_NE(b["seal_public_key"], b["public_key"]);
    EXPECT_EQ(b["pin"], "24681357");
    return reply(201, {{"device", {{"id", "ddv_NEW"}}}, {"bundle_mac_key", vectors()["mac_key_b64u"]},
                       {"offline_otp_uri", "otpauth://totp/x"}});
  };
  MemorySecretStore st;
  auto res = enrollDevice(r.config, *r.key, r.http, st, "CODE-1", "24681357", "host", "windows", "0.1.0", r.seal.get());
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
  EXPECT_EQ(r.gate->begin(true).kind, GateDecision::Kind::NotRequired);
  EXPECT_TRUE(r.gate->satisfied());
}

TEST(Gate, PushHappyPathShowsNumberMatch) {
  Rig r;
  auto d = r.gate->begin(true);
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
  r.gate->begin(true);
  r.gate->startPush();
  r.server.pushStatus = "failed";
  EXPECT_EQ(r.gate->pollPush().step, Step::Failed);
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->pollPush().step, Step::Failed);  // challenge is gone, never "verified"
}

TEST(Gate, TotpWrongThenRight) {
  Rig r;
  r.gate->begin(true);
  EXPECT_EQ(r.gate->submitCode("000000").step, Step::WrongCode);
  EXPECT_EQ(r.gate->submitCode("12ab56").step, Step::WrongCode);  // malformed: never sent
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->submitCode("123456").step, Step::Verified);
  EXPECT_TRUE(r.gate->satisfied());
  EXPECT_EQ(r.http.count("challenges"), 1u);  // one challenge reused for the retry
}

TEST(Gate, TotpFiveWrongEndsChallenge) {
  Rig r;
  r.gate->begin(true);
  Step last = Step::Pending;
  for (int i = 0; i < 5; i++) last = r.gate->submitCode("000000").step;
  EXPECT_EQ(last, Step::Failed);
  EXPECT_FALSE(r.gate->satisfied());
}

TEST(Gate, PasskeyUnsupportedUnlessHandlerInjected) {
  Rig r;
  r.server.factors = json::array({"passkey"});
  r.gate->begin(true);
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
  r.gate->begin(true);  // caches required + bundle
  r.server.revoked = true;
  auto d = r.gate->begin(true);
  EXPECT_EQ(d.kind, GateDecision::Kind::Denied);
  EXPECT_EQ(d.reason, "revoked");
  EXPECT_FALSE(r.vault->heldBundle());
  EXPECT_FALSE(r.gate->satisfied());
  // and it stays denied when the network later drops: the cache says revoked
  r.http.down = true;
  EXPECT_EQ(r.gate->begin(true).kind, GateDecision::Kind::Denied);
}

TEST(Gate, UnreachableFallsBackToOfflineUnlock) {
  Rig r;
  r.gate->begin(true);  // online: caches state and bundle
  r.http.down = true;
  auto d = r.gate->begin(true);
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
  r.gate->begin(true);
  r.http.down = true;
  r.gate->begin(true);
  for (int i = 0; i < 5; i++) r.gate->submitOffline(vectors()["pin"]["value"], "000000");
  EXPECT_EQ(r.gate->submitOffline(vectors()["pin"]["value"], "877905").step, Step::Locked);
  EXPECT_FALSE(r.gate->satisfied());
}

TEST(Gate, UnreachableWithExpiredBundleIsDenied) {
  Rig r;
  r.gate->begin(true);
  r.http.down = true;
  r.clock.now = 1800259200000 + 1000;
  auto d = r.gate->begin(true);
  EXPECT_EQ(d.kind, GateDecision::Kind::Denied);
  EXPECT_EQ(d.reason, "offline_expired");
}

TEST(Gate, UnreachableWithClockRolledBackIsDenied) {
  Rig r;
  r.gate->begin(true);
  r.http.down = true;
  r.clock.now += 2 * 24 * 3600 * 1000LL;
  r.gate->begin(true);
  r.vault->noteTime();
  r.clock.now -= 24 * 3600 * 1000LL;
  auto d = r.gate->begin(true);
  EXPECT_EQ(d.kind, GateDecision::Kind::Denied);
  EXPECT_EQ(d.reason, "clock");
}

TEST(Gate, RequiredButNoBundleAndOfflineIsDenied) {
  Rig r;
  r.server.withBundle = false;
  r.gate->begin(true);
  r.http.down = true;
  auto d = r.gate->begin(true);
  EXPECT_EQ(d.kind, GateDecision::Kind::Denied);
  EXPECT_EQ(d.reason, "offline_unavailable");
}

TEST(Gate, OfflineDisabledByPolicyIsDenied) {
  Rig r;
  r.server.offlineEnabled = false;
  r.gate->begin(true);
  r.http.down = true;
  EXPECT_EQ(r.gate->begin(true).reason, "offline_unavailable");
}

TEST(Gate, NeverSyncedFailsClosedByDefault) {
  Rig r;
  r.http.down = true;
  auto d = r.gate->begin(true);
  EXPECT_EQ(d.kind, GateDecision::Kind::Denied);
  EXPECT_EQ(d.reason, "never_synced");
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->submitOffline("1", "123456").step, Step::Unsupported);
}

TEST(Gate, NeverSyncedFailOpenOnlyWhenConfigured) {
  Rig r(true);
  r.http.down = true;
  EXPECT_EQ(r.gate->begin(true).kind, GateDecision::Kind::NotRequired);
  EXPECT_TRUE(r.gate->satisfied());
}

TEST(Gate, CachedNotRequiredAllowsWhileOffline) {
  Rig r;
  r.server.required = false;
  r.gate->begin(true);
  r.http.down = true;
  EXPECT_EQ(r.gate->begin(true).kind, GateDecision::Kind::NotRequired);
}

TEST(Gate, RequiredStaysRequiredOfflineEvenIfServerStopsAnswering) {
  Rig r;
  r.gate->begin(true);
  r.http.handler = [](const std::string&, const json&) { return HttpResponse{502, "bad gateway"}; };
  auto d = r.gate->begin(true);
  EXPECT_EQ(d.kind, GateDecision::Kind::Required);  // never silently drops to password-only
  EXPECT_FALSE(r.gate->satisfied());
}

TEST(Gate, UnreachableDuringChallengeIsNotVerified) {
  Rig r;
  r.gate->begin(true);
  r.gate->startPush();
  r.http.down = true;
  EXPECT_EQ(r.gate->pollPush().step, Step::Unreachable);
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->submitCode("123456").step, Step::Unreachable);
}

TEST(Gate, UnenrolledIsDeniedByTheCoreCallerDecidesPassthrough) {
  Rig r;
  r.config.enrolled = false;
  EXPECT_EQ(r.gate->begin(true).reason, "not_enrolled");
}

TEST(Client, EnrollWithoutSealKeyOmitsField) {
  Rig r;
  r.config.enrolled = false;
  bool absent = false;
  r.http.handler = [&](const std::string&, const json& b) {
    absent = !b.contains("seal_public_key");
    return reply(201, {{"device", {{"id", "ddv_NEW"}}}, {"bundle_mac_key", vectors()["mac_key_b64u"]}});
  };
  MemorySecretStore st;
  EXPECT_TRUE(enrollDevice(r.config, *r.key, r.http, st, "C", "", "h", "windows", "v").ok);
  EXPECT_TRUE(absent);
}

TEST(Gate, OfflineOpensWithSealKeyNotSigningKey) {
  Rig r;
  r.gate->begin(true);
  r.http.down = true;
  EXPECT_EQ(r.gate->begin(true).kind, GateDecision::Kind::Required);
  // A vault wired to the signing key (the wrong key) cannot open a bundle sealed to the seal key.
  OfflineVault wrong(r.store, r.clock, *r.key, "ddv_TESTVECTOR");
  EXPECT_EQ(wrong.status(), OfflineResult::BundleInvalid);
}

TEST(Gate, UnverifiedPasswordMakesNoNetworkCallAndNeverSatisfies) {
  Rig r;
  auto d = r.gate->begin(false);
  EXPECT_EQ(d.kind, GateDecision::Kind::Denied);
  EXPECT_EQ(d.reason, "password_not_verified");
  EXPECT_TRUE(r.http.log.empty());
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->startPush().step, Step::Unsupported);
  EXPECT_EQ(r.gate->submitCode("123456").step, Step::Unsupported);
  EXPECT_TRUE(r.http.log.empty());
}

TEST(Gate, UnverifiedPasswordDeniedEvenWhenNotRequiredOrFailOpen) {
  Rig r(true);
  r.server.required = false;
  r.gate->begin(true);  // caches required=false
  r.http.log.clear();
  EXPECT_EQ(r.gate->begin(false).kind, GateDecision::Kind::Denied);
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_TRUE(r.http.log.empty());
  Rig f(true);
  f.http.down = true;
  EXPECT_EQ(f.gate->begin(false).kind, GateDecision::Kind::Denied);
  EXPECT_TRUE(f.http.log.empty());
}

TEST(Gate, VerifiedAfterUnverifiedWorks) {
  Rig r;
  r.gate->begin(false);
  EXPECT_EQ(r.gate->begin(true).kind, GateDecision::Kind::Required);
}

// ---- passkey ceremony through the gate ----

#include "atlas/passkey.hpp"

namespace {
struct FakeAuth : IPasskeyAuthenticator {
  bool ok = true, cancelCalled = false;
  int getCalls = 0, makeCalls = 0;
  std::string lastClientData;
  bool available() override { return ok; }
  std::optional<RawAssertion> getAssertion(const PasskeyRequest&, const std::string& cd, std::string&) override {
    getCalls++;
    lastClientData = cd;
    return RawAssertion{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
  }
  std::optional<RawAttestation> makeCredential(const PasskeyCreation&, const std::string& cd, std::string&) override {
    makeCalls++;
    lastClientData = cd;
    return RawAttestation{{1, 2, 3}, {0xa1, 0x00}, {"usb"}};
  }
  void cancel() override { cancelCalled = true; }
};

json goodOptions() {
  return {{"challenge", "QUJDREVGR0hJSktMTU5PUA"}, {"rpId", "auth.example.com"}, {"origin", "https://auth.example.com"},
          {"userVerification", "required"}, {"allowCredentials", json::array({{{"type", "public-key"}, {"id", "AQID"}, {"transports", json::array({"usb"})}}})}};
}
}  // namespace

TEST(PasskeyGate, SplitCeremonyForwardsTheAssertionAndVerifies) {
  Rig r;
  r.server.factors = json::array({"passkey"});
  r.server.passkeyOptions = goodOptions();
  r.server.pushStatus = "verified";
  r.gate->begin(true);
  json opts;
  ASSERT_EQ(r.gate->startPasskey(opts).step, Step::Pending);
  EXPECT_EQ(opts["rpId"], "auth.example.com");
  FakeAuth fa;
  auto fn = makePasskeyFn(fa);
  auto a = fn(opts);
  ASSERT_TRUE(a);
  EXPECT_EQ(fa.getCalls, 1);
  EXPECT_EQ(r.gate->completePasskey(a).step, Step::Verified);
  EXPECT_TRUE(r.gate->satisfied());
  EXPECT_EQ(r.gate->lastVerifiedChallengeId(), "chl_passkey");
  // The server saw exactly what the authenticator produced, with the client data we built.
  EXPECT_EQ(r.server.lastAssertion["credential_id"], "AQID");
  EXPECT_EQ(r.server.lastAssertion["challenge"], "QUJDREVGR0hJSktMTU5PUA");
  json cd = json::parse(*b64uDecode(r.server.lastAssertion["client_data_json"]));
  EXPECT_EQ(cd["type"], "webauthn.get");
  EXPECT_EQ(cd["origin"], "https://auth.example.com");
  EXPECT_EQ(cd["challenge"], "QUJDREVGR0hJSktMTU5PUA");
  EXPECT_TRUE(r.server.badSignatures.empty());
}

TEST(PasskeyGate, CancelledOrRejectedNeverVerifiesAndNextAttemptStartsFresh) {
  Rig r;
  r.server.factors = json::array({"passkey"});
  r.server.passkeyOptions = goodOptions();
  r.gate->begin(true);
  json opts;
  ASSERT_EQ(r.gate->startPasskey(opts).step, Step::Pending);
  auto s = r.gate->completePasskey(std::nullopt);
  EXPECT_EQ(s.step, Step::Failed);
  EXPECT_EQ(s.detail, "cancelled");
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->completePasskey(std::nullopt).detail, "no_challenge");  // nothing left to answer

  r.server.rejectAssertion = true;
  ASSERT_EQ(r.gate->startPasskey(opts).step, Step::Pending);
  FakeAuth fa;
  s = r.gate->completePasskey(makePasskeyFn(fa)(opts));
  EXPECT_EQ(s.step, Step::Failed);
  EXPECT_EQ(s.detail, "passkey_rejected");
  EXPECT_FALSE(r.gate->satisfied());
  EXPECT_EQ(r.gate->completePasskey(makePasskeyFn(fa)(opts)).detail, "no_challenge");
}

TEST(PasskeyGate, OnlyWhenTheServerAllowsItAndOnline) {
  Rig r;
  r.server.factors = json::array({"totp"});
  r.gate->begin(true);
  json opts;
  EXPECT_EQ(r.gate->startPasskey(opts).step, Step::Unsupported);
  EXPECT_EQ(r.http.count("challenges"), 0u);
}

TEST(PasskeyGate, MalformedServerOptionsNeverReachTheAuthenticator) {
  FakeAuth fa;
  auto fn = makePasskeyFn(fa);
  json o = goodOptions();
  o["origin"] = "https://evil.example";  // not https://<rpId>
  EXPECT_FALSE(fn(o));
  o = goodOptions();
  o["challenge"] = "short";
  EXPECT_FALSE(fn(o));
  EXPECT_EQ(fa.getCalls, 0);
  fa.ok = false;  // platform API missing
  EXPECT_FALSE(fn(goodOptions()));
  EXPECT_EQ(fa.getCalls, 0);
}

TEST(PasskeyEnrol, RunsThroughProofOptionsAuthenticatorAndFinish) {
  Rig r;
  FakeAuth fa;
  auto res = enrollPasskey(*r.client, fa, "chl_totp", "Desk key");
  ASSERT_TRUE(res.ok) << res.error;
  EXPECT_EQ(res.passkeyId, "ddp_1");
  EXPECT_EQ(fa.makeCalls, 1);
  EXPECT_EQ(r.server.lastRegistration, "chl_totp");
  EXPECT_EQ(r.server.lastCredential["attestation_object"], b64uEncode(Bytes{0xa1, 0x00}));
  json cd = json::parse(*b64uDecode(r.server.lastCredential["client_data_json"]));
  EXPECT_EQ(cd["type"], "webauthn.create");
  EXPECT_EQ(cd["origin"], "https://auth.example.com");
  EXPECT_TRUE(r.server.badSignatures.empty());
}

TEST(PasskeyEnrol, RefusedProofOrMissingPlatformSupportStopsBeforeTheAuthenticator) {
  Rig r;
  FakeAuth fa;
  auto res = enrollPasskey(*r.client, fa, "chl_other", "k");
  EXPECT_FALSE(res.ok);
  EXPECT_EQ(res.error, "verification_failed");
  EXPECT_EQ(fa.makeCalls, 0);
  fa.ok = false;
  EXPECT_FALSE(enrollPasskey(*r.client, fa, "chl_totp", "k").ok);
  EXPECT_EQ(r.http.count("passkeys/options"), 1u);  // the second attempt never called the server
  fa.ok = true;
  r.http.down = true;
  EXPECT_EQ(enrollPasskey(*r.client, fa, "chl_totp", "k").error, "server unreachable");
}

// ---- command-line MFA (CliSession behind cliAuthenticate) ----

namespace {
struct CliRig {
  Rig r;
  std::vector<std::string> infos, sent;
  std::deque<std::string> replies, answers;
  std::unique_ptr<CliSession> session;
  explicit CliRig(CliSession::Mode mode = CliSession::Mode::Gate, int maxPolls = 3, const std::string& why = "") {
    session = std::make_unique<CliSession>(r.config, mode, why, r.gate.get(), CliSession::Who{"", "alice", "PC-1"},
                                           [](const std::function<void()>& f) { f(); }, [](int) {}, maxPolls);
  }
  bool run(const std::string& service = "sshd") {
    CliIo io;
    io.send = [&](const std::string& l) {
      sent.push_back(l);
      session->handle(l, [&](const std::string& o) { replies.push_back(o); });
      return true;
    };
    io.recv = [&](std::string& out, int) {
      if (replies.empty()) return false;
      out = replies.front();
      replies.pop_front();
      return true;
    };
    io.info = [&](const std::string& m) { infos.push_back(m); };
    io.prompt = [&](const std::string&, bool, std::string& out) {
      if (answers.empty()) return false;
      out = answers.front();
      answers.pop_front();
      return true;
    };
    return cliAuthenticate(io, service);
  }
  std::string handle(const std::string& line) {
    std::string last;
    session->handle(line, [&](const std::string& o) { last = o; });
    return last;
  }
};
}  // namespace

TEST(Cli, PushApprovedAllows) {
  CliRig c;
  c.r.server.pushStatus = "verified";
  EXPECT_TRUE(c.run());
  EXPECT_TRUE(c.session->allowed());
  ASSERT_FALSE(c.infos.empty());
  EXPECT_NE(c.infos[0].find("47"), std::string::npos);  // the number to pick is shown
}

TEST(Cli, PushNeverApprovedFallsBackToTheCode) {
  CliRig c;
  c.answers = {"123456"};
  EXPECT_TRUE(c.run());
}

TEST(Cli, WrongCodesRefuseAfterThreeTries) {
  CliRig c;
  c.answers = {"000001", "000002", "000003"};
  EXPECT_FALSE(c.run());
  EXPECT_FALSE(c.session->allowed());
}

TEST(Cli, NonNumericInputIsNotSentToTheServer) {
  CliRig c;
  c.answers = {"abc", "12 456", "123456"};
  EXPECT_TRUE(c.run());
  for (auto& l : c.sent) EXPECT_TRUE(l.rfind("CODE ", 0) != 0 || l == "CODE 123456") << l;
}

TEST(Cli, OfflineWithPinAndCodeWhenTheServerIsDown) {
  CliRig c;
  ASSERT_EQ(c.r.sync->run(), SyncOutcome::Ok);  // fetches the offline bundle
  c.r.http.down = true;
  c.answers = {vectors()["pin"]["value"].get<std::string>(), "877905"};
  EXPECT_TRUE(c.run());
  CliRig d;
  ASSERT_EQ(d.r.sync->run(), SyncOutcome::Ok);
  d.r.http.down = true;
  d.answers = {vectors()["pin"]["value"].get<std::string>(), "000000", vectors()["pin"]["value"].get<std::string>(), "000000", vectors()["pin"]["value"].get<std::string>(), "000000"};
  EXPECT_FALSE(d.run());
}

TEST(Cli, NotRequiredAndBreakGlassAndPassthroughAllow) {
  CliRig a;
  a.r.server.required = false;
  EXPECT_TRUE(a.run());
  CliRig b;
  b.r.config.breakGlassAccounts = {"alice"};
  b.r.http.down = true;  // no network needed
  EXPECT_TRUE(b.run());
  EXPECT_EQ(b.r.http.log.size(), 0u);
  CliRig p(CliSession::Mode::Passthrough, 3, "not enrolled");
  EXPECT_TRUE(p.run());
}

TEST(Cli, BrokenInstallAndNeverSyncedFailClosed) {
  CliRig broken(CliSession::Mode::Broken, 3, "device key missing");
  EXPECT_FALSE(broken.run());
  CliRig offline;
  offline.r.http.down = true;  // never synced and unreachable
  EXPECT_FALSE(offline.run());
  EXPECT_FALSE(offline.session->allowed());
}

TEST(Cli, ProtocolMisuseIsRefused) {
  CliRig c;
  EXPECT_EQ(c.handle("CODE 123456"), "REJECT bad request");  // before BEGIN
  CliRig d;
  EXPECT_EQ(d.handle("BEGIN bad;service"), "DENY bad request");
  CliRig e;
  EXPECT_EQ(e.handle("BEGIN"), "DENY bad request");
  CliRig f;
  f.handle("BEGIN sshd");
  EXPECT_EQ(f.handle("BEGIN sshd"), "DENY bad request");  // second BEGIN
  EXPECT_EQ(f.handle("CODE 12345"), "REJECT bad request");
  EXPECT_EQ(f.handle("OFFLINE 123 123456"), "REJECT bad request");
  EXPECT_FALSE(f.session->allowed());
}

TEST(Cli, PasskeyOnlyPolicyHasNoConsoleFactor) {
  CliRig c;
  c.r.server.factors = json::array({"passkey"});
  c.r.server.withBundle = false;
  EXPECT_FALSE(c.run());
  ASSERT_FALSE(c.infos.empty());
  EXPECT_NE(c.infos[0].find("no usable factor"), std::string::npos);
}
