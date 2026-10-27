#include <gtest/gtest.h>

#include "fixture.hpp"

using namespace atlas;
using t::vectors;

TEST(Base64Url, RoundTripAndRejects) {
  for (size_t n = 0; n < 40; n++) {
    Bytes b = randomBytes(n);
    auto d = b64uDecode(b64uEncode(b));
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(*d, b);
  }
  EXPECT_EQ(b64uEncode(std::string("\xfb\xff")), "-_8");
  EXPECT_FALSE(b64uDecode("AA==").has_value());
  EXPECT_FALSE(b64uDecode("A").has_value());
  EXPECT_FALSE(b64uDecode("A B").has_value());
  EXPECT_FALSE(b64uDecode("+/").has_value());
}

TEST(ConstantTime, Compare) {
  EXPECT_TRUE(ctEqual(std::string("abc"), std::string("abc")));
  EXPECT_FALSE(ctEqual(std::string("abc"), std::string("abd")));
  EXPECT_FALSE(ctEqual(std::string("abc"), std::string("abcd")));
  EXPECT_TRUE(ctEqual(Bytes{}, Bytes{}));
}

TEST(Base32, Decodes) {
  auto b = base32Decode("MFRGG===");
  ASSERT_TRUE(b);
  EXPECT_EQ(toString(*b), "abc");
  EXPECT_FALSE(base32Decode("1!").has_value());
}

static std::string hex(const Bytes& b) {
  static const char* d = "0123456789abcdef";
  std::string o;
  for (uint8_t c : b) { o += d[c >> 4]; o += d[c & 15]; }
  return o;
}

TEST(Crypto, Primitives) {
  EXPECT_EQ(b64uEncode(sha256(toBytes("abc"))), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
  // RFC 4231 test case 2
  Bytes mac = hmac("SHA256", toBytes("Jefe"), toBytes("what do ya want for nothing?"));
  EXPECT_EQ(hex(mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  // RFC 5869 test case 1
  Bytes ikm(22, 0x0b), salt, info = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
  for (uint8_t i = 0; i <= 0x0c; i++) salt.push_back(i);
  Bytes okm = hkdfSha256(ikm, salt, info, 42);
  ASSERT_EQ(okm.size(), 42u);
  EXPECT_EQ(okm[0], 0x3c);
  EXPECT_EQ(okm[1], 0xb2);
  EXPECT_EQ(okm[41], 0x65);
}

TEST(Crypto, ScryptBoundsRejected) {
  EXPECT_FALSE(scryptDerive("x", Bytes(16, 1), 3, 8, 1, 32));          // N not a power of two
  EXPECT_FALSE(scryptDerive("x", Bytes(16, 1), 1u << 21, 8, 1, 32));   // too much memory
}

TEST(SoftKey, VectorPublicJwkMatches) {
  auto k = t::vectorKey();
  ASSERT_TRUE(k);
  json pub = k->publicJwk();
  EXPECT_EQ(pub["x"], vectors()["device_public_jwk"]["x"]);
  EXPECT_EQ(pub["y"], vectors()["device_public_jwk"]["y"]);
  EXPECT_EQ(pub["crv"], "P-256");
}

TEST(SoftKey, SignatureIsP1363AndVerifies) {
  auto k = SoftwareDeviceKey::generate();
  ASSERT_TRUE(k);
  Bytes msg = toBytes("hello");
  Bytes sig = k->sign(msg);
  ASSERT_EQ(sig.size(), 64u);
  EXPECT_TRUE(ecdsaVerifyP1363(k->publicJwk(), msg, sig));
  EXPECT_FALSE(ecdsaVerifyP1363(k->publicJwk(), toBytes("hellp"), sig));
  sig[10] ^= 1;
  EXPECT_FALSE(ecdsaVerifyP1363(k->publicJwk(), msg, sig));
}

TEST(SoftKey, EcdhAgrees) {
  auto a = SoftwareDeviceKey::generate(), b = SoftwareDeviceKey::generate();
  auto pt = [](SoftwareDeviceKey& k) {
    json j = k.publicJwk();
    Bytes p{4};
    for (const char* c : {"x", "y"}) { auto d = *b64uDecode(j[c]); p.insert(p.end(), d.begin(), d.end()); }
    return p;
  };
  Bytes s1 = a->ecdh(pt(*b)), s2 = b->ecdh(pt(*a));
  ASSERT_EQ(s1.size(), 32u);
  EXPECT_EQ(s1, s2);
  EXPECT_TRUE(a->ecdh(Bytes(65, 4)).empty());  // off-curve point
}

TEST(SignedMessage, MatchesVectorAndVectorSignatureVerifies) {
  const json& v = vectors()["signed_message"];
  std::string m = signedMessage(v["purpose"], v["instance_id"], v["key_id"], v["nonce"]);
  EXPECT_EQ(m, v["message"]);
  EXPECT_EQ(signedMessage("sync", "i", "k", "n", std::string("-")), "atlas-desktop:v1:sync:i:k:n:-");
  Bytes sig = *b64uDecode(v["signature_p1363_b64u"]);
  EXPECT_TRUE(ecdsaVerifyP1363(vectors()["device_public_jwk"], toBytes(m), sig));
  // Our own signature over the same message verifies too (ECDSA is randomised, so compare by verifying).
  auto k = t::vectorKey();
  EXPECT_TRUE(ecdsaVerifyP1363(vectors()["device_public_jwk"], toBytes(m), k->sign(toBytes(m))));
}

TEST(Bundle, MacMatchesVectorAndDetectsTamper) {
  Bytes mk = *b64uDecode(vectors()["mac_key_b64u"]);
  Bundle b = t::vectorBundle();
  EXPECT_EQ(bundleMac(mk, "ddv_TESTVECTOR", b), b.mac);
  EXPECT_TRUE(bundleMacOk(mk, "ddv_TESTVECTOR", b));
  EXPECT_FALSE(bundleMacOk(mk, "ddv_OTHER", b));
  Bundle g = b; g.generation++;
  EXPECT_FALSE(bundleMacOk(mk, "ddv_TESTVECTOR", g));
  g = b; g.expiresAt++;
  EXPECT_FALSE(bundleMacOk(mk, "ddv_TESTVECTOR", g));
  g = b; g.sealed[5] = g.sealed[5] == 'A' ? 'B' : 'A';
  EXPECT_FALSE(bundleMacOk(mk, "ddv_TESTVECTOR", g));
  g = b; g.mac = "AAAA";
  EXPECT_FALSE(bundleMacOk(mk, "ddv_TESTVECTOR", g));
  EXPECT_FALSE(bundleMacOk(Bytes{}, "ddv_TESTVECTOR", b));
}

TEST(Bundle, OpensVectorSealedBox) {
  auto k = t::vectorKey();
  auto p = openBundle(*k, vectors()["bundle"]["sealed"]);
  ASSERT_TRUE(p);
  const json& pl = vectors()["bundle"]["plaintext"];
  EXPECT_EQ(p->bundleId, pl["bundle_id"]);
  EXPECT_EQ(p->deviceId, pl["device_id"]);
  EXPECT_EQ(p->userId, pl["user_id"]);
  EXPECT_EQ(p->generation, pl["generation"].get<int64_t>());
  EXPECT_EQ(p->issuedAt, pl["issued_at"].get<int64_t>());
  EXPECT_EQ(p->expiresAt, pl["expires_at"].get<int64_t>());
  EXPECT_TRUE(p->pinRequired);
  ASSERT_TRUE(p->pin);
  EXPECT_EQ(p->pin->hash, pl["pin"]["hash"]);
  EXPECT_EQ(p->totp.secret, pl["totp"]["secret"]);
}

TEST(Bundle, OpenFailsForWrongKeyTamperAndTruncation) {
  const std::string sealed = vectors()["bundle"]["sealed"];
  auto other = SoftwareDeviceKey::generate();
  EXPECT_FALSE(openBundle(*other, sealed));
  auto k = t::vectorKey();
  std::string tampered = sealed;
  tampered[200] = tampered[200] == 'A' ? 'B' : 'A';
  EXPECT_FALSE(openBundle(*k, tampered));
  EXPECT_FALSE(openBundle(*k, sealed.substr(0, 60)));
  EXPECT_FALSE(openBundle(*k, ""));
  Bytes raw = *b64uDecode(sealed);
  raw[0] = 2;
  EXPECT_FALSE(openBundle(*k, b64uEncode(raw)));
}

TEST(Pin, ScryptVerifier) {
  const json& p = vectors()["pin"];
  PinVerifier v{p["verifier"]["N"], p["verifier"]["r"], p["verifier"]["p"], p["verifier"]["salt"], p["verifier"]["hash"]};
  EXPECT_TRUE(verifyPin(p["value"], v));
  EXPECT_FALSE(verifyPin(p["wrong"], v));
  EXPECT_FALSE(verifyPin("", v));
  v.hash = "AAAA";
  EXPECT_FALSE(verifyPin(p["value"], v));
}

TEST(Totp, Vectors) {
  const json& tv = vectors()["totp"];
  for (const auto& e : tv["times"]) EXPECT_EQ(totpCode(tv["secret"], e["unix"]), e["code"]) << e["unix"];
}

TEST(Totp, WindowAndReplay) {
  const std::string s = vectors()["totp"]["secret"];
  int64_t now = 1800000000;
  std::string cur = totpCode(s, now), prev = totpCode(s, now - 30), next = totpCode(s, now + 30), far = totpCode(s, now + 90);
  EXPECT_EQ(totpMatch(s, cur, now, -1), now / 30);
  EXPECT_EQ(totpMatch(s, prev, now, -1), now / 30 - 1);
  EXPECT_EQ(totpMatch(s, next, now, -1), now / 30 + 1);
  EXPECT_FALSE(totpMatch(s, far, now, -1));
  EXPECT_FALSE(totpMatch(s, cur, now, now / 30));      // replay of the accepted step
  EXPECT_FALSE(totpMatch(s, prev, now, now / 30));     // older than the high-water step
  EXPECT_FALSE(totpMatch(s, "12345", now, -1));
}

// ---- config ----

TEST(Config, SealKeyIdOptional) {
  auto c = parseConfig(R"({"instance_url":"https://a.b","publishable_key":"pk","instance_id":"i","seal_key_id":"seal-1"})");
  ASSERT_TRUE(c.config);
  EXPECT_EQ(c.config->sealKeyId, "seal-1");
  EXPECT_EQ(parseConfig(c.config->toJson().dump()).config->sealKeyId, "seal-1");
  EXPECT_TRUE(parseConfig(R"({"instance_url":"https://a.b","publishable_key":"pk","instance_id":"i"})").config->sealKeyId.empty());
}

TEST(Config, ParsesAndValidates) {
  auto ok = parseConfig(R"({"instance_url":"https://auth.example.com/","publishable_key":"pk","instance_id":"ins_1",
    "device_id":"ddv_1","device_key_id":"k","enrolled":true,"fail_open_when_never_synced":true})");
  ASSERT_TRUE(ok.config) << ok.error;
  EXPECT_EQ(ok.config->baseUrl(), "https://auth.example.com");
  EXPECT_TRUE(ok.config->failOpenWhenNeverSynced);
  auto un = parseConfig(R"({"instance_url":"https://a.b","publishable_key":"pk","instance_id":"ins_1"})");
  ASSERT_TRUE(un.config);
  EXPECT_FALSE(un.config->enrolled);
  EXPECT_FALSE(un.config->failOpenWhenNeverSynced);
  for (const char* bad : {
           "not json", "[]", R"({"instance_url":"http://a.b","publishable_key":"pk","instance_id":"i"})",
           R"({"instance_url":"https://a.b","publishable_key":"","instance_id":"i"})",
           R"({"instance_url":"https://a.b","publishable_key":"pk"})",
           R"({"instance_url":"https://a.b","publishable_key":"pk","instance_id":"i","enrolled":true})",
           R"({"instance_url":"https://a.b","publishable_key":"pk","instance_id":"i","enrolled":"yes"})",
           R"({"instance_url":5,"publishable_key":"pk","instance_id":"i"})"})
    EXPECT_FALSE(parseConfig(bad).config) << bad;
}

// ---- offline vault ----

namespace {
struct Vault {
  MemorySecretStore store;
  t::TestClock clock;
  std::unique_ptr<SoftwareDeviceKey> key = t::vectorKey();
  OfflineVault vault{store, clock, *key, "ddv_TESTVECTOR"};
  Vault() { putString(store, "mac_key", vectors()["mac_key_b64u"]); }
  std::string code(int64_t atMs) { return totpCode(vectors()["totp"]["secret"], atMs / 1000); }
  const std::string pin = vectors()["pin"]["value"];
};
}  // namespace

TEST(OfflineVault, StoreRequiresValidMac) {
  Vault v;
  Bundle bad = t::vectorBundle();
  bad.mac = "AAAA";
  EXPECT_FALSE(v.vault.storeBundle(bad));
  EXPECT_FALSE(v.vault.heldBundle());
  EXPECT_TRUE(v.vault.storeBundle(t::vectorBundle()));
  EXPECT_EQ(v.vault.heldBundle()->bundleId, "ddb_TESTVECTOR");
  v.store.remove("mac_key");
  EXPECT_FALSE(v.vault.storeBundle(t::vectorBundle()));
}

TEST(OfflineVault, UnlockHappyPath) {
  Vault v;
  EXPECT_EQ(v.vault.unlock(v.pin, "877905"), OfflineResult::NoBundle);
  ASSERT_TRUE(v.vault.storeBundle(t::vectorBundle()));
  EXPECT_EQ(v.vault.status(), OfflineResult::Ok);
  EXPECT_TRUE(v.vault.pinRequired());
  EXPECT_EQ(v.vault.unlock(v.pin, "877905"), OfflineResult::Ok);
  auto ev = v.vault.events();
  ASSERT_FALSE(ev.empty());
  EXPECT_EQ(ev.back().outcome, "success");
  EXPECT_EQ(ev.back().bundleId, "ddb_TESTVECTOR");
}

TEST(OfflineVault, WrongPinAndWrongCodeAreRefused) {
  Vault v;
  ASSERT_TRUE(v.vault.storeBundle(t::vectorBundle()));
  EXPECT_EQ(v.vault.unlock("00000000", "877905"), OfflineResult::WrongCredentials);
  EXPECT_EQ(v.vault.unlock(v.pin, "000000"), OfflineResult::WrongCredentials);
  EXPECT_EQ(v.vault.unlock(v.pin, "877905"), OfflineResult::Ok);  // the failed tries did not burn the step
}

TEST(OfflineVault, FiveWrongAttemptsLockForFifteenMinutesAndPersist) {
  Vault v;
  ASSERT_TRUE(v.vault.storeBundle(t::vectorBundle()));
  for (int i = 0; i < 5; i++) EXPECT_EQ(v.vault.unlock(v.pin, "000000"), OfflineResult::WrongCredentials);
  EXPECT_EQ(v.vault.unlock(v.pin, "877905"), OfflineResult::Locked);  // correct credentials, still locked
  OfflineVault again(v.store, v.clock, *v.key, "ddv_TESTVECTOR");     // lock lives in the store, not the object
  EXPECT_EQ(again.unlock(v.pin, "877905"), OfflineResult::Locked);
  v.clock.now += 14 * 60 * 1000;
  EXPECT_EQ(again.unlock(v.pin, v.code(v.clock.now)), OfflineResult::Locked);
  v.clock.now += 61 * 1000;
  EXPECT_EQ(again.unlock(v.pin, v.code(v.clock.now)), OfflineResult::Ok);
}

TEST(OfflineVault, ReplayedStepRefused) {
  Vault v;
  ASSERT_TRUE(v.vault.storeBundle(t::vectorBundle()));
  EXPECT_EQ(v.vault.unlock(v.pin, "877905"), OfflineResult::Ok);
  EXPECT_EQ(v.vault.unlock(v.pin, "877905"), OfflineResult::WrongCredentials);
  v.clock.now += 30 * 1000;
  EXPECT_EQ(v.vault.unlock(v.pin, v.code(v.clock.now)), OfflineResult::Ok);  // next step is fine
}

TEST(OfflineVault, ExpiredBundleRefused) {
  Vault v;
  ASSERT_TRUE(v.vault.storeBundle(t::vectorBundle()));
  v.clock.now = 1800259200000;  // == expires_at
  EXPECT_EQ(v.vault.status(), OfflineResult::Expired);
  EXPECT_EQ(v.vault.unlock(v.pin, v.code(v.clock.now)), OfflineResult::Expired);
  v.clock.now = 1800259200000 - 1000;
  EXPECT_EQ(v.vault.unlock(v.pin, v.code(v.clock.now)), OfflineResult::Ok);
}

TEST(OfflineVault, ClockRollbackRefused) {
  Vault v;
  ASSERT_TRUE(v.vault.storeBundle(t::vectorBundle()));
  v.clock.now += 2 * 24 * 3600 * 1000LL;
  EXPECT_EQ(v.vault.unlock(v.pin, v.code(v.clock.now)), OfflineResult::Ok);  // raises the high-water mark
  v.clock.now -= 24 * 3600 * 1000LL;                                        // wound back a day
  EXPECT_EQ(v.vault.unlock(v.pin, v.code(v.clock.now)), OfflineResult::ClockRollback);
  v.clock.now += 24 * 3600 * 1000LL - 60 * 1000;  // within the 5 minute slack of the mark
  EXPECT_EQ(v.vault.status(), OfflineResult::Ok);
  EXPECT_EQ(v.vault.unlock(v.pin, v.code(v.clock.now)), OfflineResult::WrongCredentials);  // clock fine, but that step was used
}

TEST(OfflineVault, ClockBeforeIssuedAtRefused) {
  Vault v;
  ASSERT_TRUE(v.vault.storeBundle(t::vectorBundle()));
  v.clock.now = 1800000000000 - 10 * 60 * 1000;
  EXPECT_EQ(v.vault.status(), OfflineResult::ClockRollback);
}

TEST(OfflineVault, TamperedStoredBundleRefused) {
  Vault v;
  ASSERT_TRUE(v.vault.storeBundle(t::vectorBundle()));
  json j = *getJson(v.store, "bundle");
  j["expires_at"] = j["expires_at"].get<int64_t>() + 1000000;  // try to extend validity
  putJson(v.store, "bundle", j);
  EXPECT_EQ(v.vault.unlock(v.pin, "877905"), OfflineResult::BundleInvalid);
  j = *getJson(v.store, "bundle");
  j["expires_at"] = j["expires_at"].get<int64_t>() - 1000000;
  j["mac"] = "AAAA";
  putJson(v.store, "bundle", j);
  EXPECT_EQ(v.vault.status(), OfflineResult::BundleInvalid);
}

TEST(OfflineVault, BundleForAnotherDeviceRefused) {
  Vault v;
  OfflineVault other(v.store, v.clock, *v.key, "ddv_OTHER");
  EXPECT_FALSE(other.storeBundle(t::vectorBundle()));  // MAC binds the device id
}

TEST(OfflineVault, EventQueueDrops) {
  Vault v;
  ASSERT_TRUE(v.vault.storeBundle(t::vectorBundle()));
  v.vault.unlock(v.pin, "000000");
  v.vault.unlock(v.pin, "877905");
  ASSERT_EQ(v.vault.events().size(), 2u);
  EXPECT_EQ(v.vault.events()[0].outcome, "failure");
  v.vault.dropEvents(1);
  ASSERT_EQ(v.vault.events().size(), 1u);
  EXPECT_EQ(v.vault.events()[0].outcome, "success");
}

// ---- policy ----
#include "atlas/policy.hpp"

TEST(Policy, HideStockRules) {
  HideInputs i;
  i.enrolled = true; i.cacheKnown = true; i.cacheRequired = true;
  EXPECT_TRUE(shouldHideStockProvider(i));
  i.killSwitch = true;
  EXPECT_FALSE(shouldHideStockProvider(i));  // kill switch always wins
  i = {}; i.enrolled = true; i.cacheKnown = true; i.cacheRequired = false; i.offlineBundleValid = true;
  EXPECT_FALSE(shouldHideStockProvider(i));  // MFA not required: nothing to protect
  i = {}; i.cacheKnown = true; i.cacheRequired = true;
  EXPECT_FALSE(shouldHideStockProvider(i));  // not enrolled
  i = {}; i.enrolled = true;
  EXPECT_FALSE(shouldHideStockProvider(i));  // never synced: stock stays
  i.failClosedHide = true;
  EXPECT_TRUE(shouldHideStockProvider(i));
  i.killSwitch = true;
  EXPECT_FALSE(shouldHideStockProvider(i));
  i = {}; i.enrolled = true; i.offlineBundleValid = true;
  EXPECT_TRUE(shouldHideStockProvider(i));   // bundle but no cache: still protected
}

TEST(Policy, StockProviderList) {
  EXPECT_TRUE(isStockPasswordTypeProvider("{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}"));
  EXPECT_TRUE(isStockPasswordTypeProvider("{cb82ea12-9f71-446d-89e1-8d0924e1256e}"));   // PIN logon provider
  EXPECT_FALSE(isStockPasswordTypeProvider("{D6886603-9D2F-4EB2-B667-1971041FA96B}"));  // Hello stays by default
  EXPECT_TRUE(isStockPasswordTypeProvider("{D6886603-9D2F-4EB2-B667-1971041FA96B}", true));
  EXPECT_TRUE(isStockPasswordTypeProvider("{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}"));
  EXPECT_FALSE(isStockPasswordTypeProvider("{C3B1A0E6-6D1F-4B0E-9C57-2F1B7A9D4E58}"));  // ours is never hidden
  EXPECT_FALSE(isStockPasswordTypeProvider(""));
}

TEST(Policy, BreakGlassMatching) {
  Config c;
  c.breakGlassAccounts = {"AtlasBreakGlass", "CORP\\admin2"};
  EXPECT_TRUE(isBreakGlass(c, "PC1", "atlasbreakglass", "PC1"));
  EXPECT_TRUE(isBreakGlass(c, ".", "AtlasBreakGlass", "PC1"));
  EXPECT_TRUE(isBreakGlass(c, "", "AtlasBreakGlass", "PC1"));
  EXPECT_FALSE(isBreakGlass(c, "CORP", "AtlasBreakGlass", "PC1"));  // a domain account of that name is not the local one
  EXPECT_TRUE(isBreakGlass(c, "corp", "ADMIN2", "PC1"));
  EXPECT_FALSE(isBreakGlass(c, "PC1", "admin2", "PC1"));
  EXPECT_FALSE(isBreakGlass(c, "PC1", "alice", "PC1"));
  EXPECT_FALSE(isBreakGlass(Config{}, "PC1", "AtlasBreakGlass", "PC1"));  // default list is empty
}

TEST(Policy, ConfigBreakGlassAndFailClosedHide) {
  auto c = parseConfig(R"({"instance_url":"https://a.b","publishable_key":"pk","instance_id":"i","fail_closed_hide":true,"break_glass_accounts":["AtlasBreakGlass"]})");
  ASSERT_TRUE(c.config);
  EXPECT_TRUE(c.config->failClosedHide);
  EXPECT_EQ(c.config->breakGlassAccounts, std::vector<std::string>{"AtlasBreakGlass"});
  EXPECT_EQ(parseConfig(c.config->toJson().dump()).config->breakGlassAccounts.size(), 1u);
  EXPECT_FALSE(parseConfig(R"({"instance_url":"https://a.b","publishable_key":"pk","instance_id":"i","break_glass_accounts":"x"})").config);
  EXPECT_FALSE(parseConfig(R"({"instance_url":"https://a.b","publishable_key":"pk","instance_id":"i","break_glass_accounts":[""]})").config);
}

TEST(Policy, LogonErrorClassification) {
  EXPECT_EQ(classifyLogonUserError(0), PasswordCheck::Verified);
  EXPECT_EQ(classifyLogonUserError(1907), PasswordCheck::Verified);  // must change: stock handles it after MFA
  EXPECT_EQ(classifyLogonUserError(1330), PasswordCheck::Verified);
  EXPECT_EQ(classifyLogonUserError(1385), PasswordCheck::Verified);
  EXPECT_EQ(classifyLogonUserError(1326), PasswordCheck::Wrong);
  EXPECT_EQ(classifyLogonUserError(1331), PasswordCheck::Wrong);
  EXPECT_EQ(classifyLogonUserError(1909), PasswordCheck::Wrong);
  EXPECT_EQ(classifyLogonUserError(1311), PasswordCheck::Indeterminate);
  EXPECT_EQ(classifyLogonUserError(99999), PasswordCheck::Indeterminate);
  EXPECT_TRUE(logonErrorNeedsInteractiveFallback(1311));
  EXPECT_FALSE(logonErrorNeedsInteractiveFallback(1326));
}
