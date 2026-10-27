// SsoClient against a stand-in for the Atlas device_sso endpoints that enforces DEVICE_SSO.md: every signature is verified with the
// registered key, the embedded assertion with the user key, nonces are single use, the JWE is sealed to the registered encryption key.
#include <gtest/gtest.h>

#include <map>
#include <set>

#include "atlas/devicesso.hpp"
#include "atlas/softkey.hpp"
#include "fixture.hpp"
#include "../src/core/crypto_internal.hpp"

using namespace atlas;

namespace {
const char* kBase = "https://auth.example.com";
const char* kApi = "https://auth.example.com/v1/client/device_sso/";

std::string seg(const std::string& s, int idx) {
  size_t a = 0;
  for (int i = 0; i < idx; i++) a = s.find('.', a) + 1;
  size_t b = s.find('.', a);
  return s.substr(a, b == std::string::npos ? std::string::npos : b - a);
}
json jsonSeg(const std::string& s, int idx) { return json::parse(toString(*b64uDecode(seg(s, idx)))); }
std::map<std::string, std::string> form(const std::string& body) {
  std::map<std::string, std::string> m;
  size_t at = 0;
  while (at <= body.size()) {
    size_t amp = body.find('&', at);
    std::string kv = body.substr(at, amp == std::string::npos ? std::string::npos : amp - at);
    size_t eq = kv.find('=');
    std::string v = kv.substr(eq + 1), d;
    for (size_t i = 0; i < v.size(); i++) {
      if (v[i] == '%' && i + 2 < v.size() + 0) { d += static_cast<char>(std::stoi(v.substr(i + 1, 2), nullptr, 16)); i += 2; }
      else d += v[i];
    }
    m[kv.substr(0, eq)] = d;
    if (amp == std::string::npos) break;
    at = amp + 1;
  }
  return m;
}

struct Idp : IHttpClient {
  std::unique_ptr<SoftwareDeviceKey> instanceKey = SoftwareDeviceKey::generate();
  std::unique_ptr<SoftwareDeviceKey> eph = SoftwareDeviceKey::generate();
  bool enabled = true, revoked = false;
  std::string code = "dsk_abc";
  std::string regId = "dsso_1";
  json signingPub, encPub, userPub;
  std::set<std::string> nonces;
  int n = 0, refreshN = 0;
  std::string refreshToken;  // the one live token
  std::vector<std::string> reasons;
  bool badIdToken = false;
  std::string tokenEndpoint = std::string(kApi) + "token";

  static HttpResponse j(int s, const json& b) { return {s, b.dump()}; }
  HttpResponse err(int s, const char* c) { reasons.push_back(c); return j(s, {{"errors", json::array({{{"code", c}}})}}); }

  HttpResponse get(const std::string& url, const std::vector<std::pair<std::string, std::string>>&) override {
    if (url == std::string(kApi) + "configuration")
      return j(200, {{"enabled", enabled}, {"instance_id", "ins_1"}, {"issuer", kBase}, {"client_id", "pk_1"}, {"audience", kBase},
                     {"token_endpoint", tokenEndpoint}, {"nonce_endpoint", tokenEndpoint}, {"jwks_uri", std::string(kBase) + "/.well-known/jwks.json"},
                     {"protocol_version", 1}, {"session_minutes", 480}, {"refresh_days", 30}});
    if (url == std::string(kBase) + "/.well-known/jwks.json") {
      json k = instanceKey->publicJwk();
      k["kid"] = "ik"; k["alg"] = "ES256";
      return j(200, {{"keys", json::array({k})}});
    }
    return {404, ""};
  }

  bool sigOk(const json& pub, const std::string& msg, const std::string& sig) {
    auto s = b64uDecode(sig);
    return s && ecdsaVerifyP1363(pub, toBytes(msg), *s);
  }

  HttpResponse post(const std::string& url, const std::vector<std::pair<std::string, std::string>>&, const std::string& body) override {
    if (url == tokenEndpoint) return token(form(body));
    json b = json::parse(body, nullptr, false);
    if (url == std::string(kApi) + "register_device") {
      std::string kid = jwkKid(b["signing_public_key"]);
      if (b["registration_token"] != code) return err(401, "verification_failed");
      if (!sigOk(b["signing_public_key"], signedMessage("sso_device", "ins_1", kid, code), b["signature"])) return err(401, "verification_failed");
      signingPub = b["signing_public_key"]; encPub = b["encryption_public_key"];
      code = "used";
      return j(201, {{"object", "device_sso_registration"}, {"id", regId}, {"user_id", "usr_1"}, {"status", "active"}});
    }
    if (url == std::string(kApi) + "register_user") {
      if (!nonces.erase(b["nonce"])) return err(401, "nonce");
      if (!sigOk(signingPub, signedMessage("sso_user", "ins_1", regId, b["nonce"], jwkKid(b["user_public_key"])), b["signature"])) return err(401, "verification_failed");
      userPub = b["user_public_key"];
      return j(200, {{"id", regId}, {"user_key_registered", true}});
    }
    if (url == std::string(kApi) + "web_session") {
      if (!nonces.erase(b["nonce"])) return err(401, "nonce");
      if (revoked || refreshToken.empty()) return err(403, "forbidden");
      if (!sigOk(signingPub, signedMessage("sso_web", "ins_1", regId, b["nonce"]), b["signature"])) return err(401, "verification_failed");
      return j(201, {{"ticket", "t1"}, {"expires_at", 1}, {"ticket_url", std::string(kBase) + "/v1/client/sign_in?ticket=t1"}});
    }
    return {404, ""};
  }

  HttpResponse token(const std::map<std::string, std::string>& f) {
    if (f.at("grant_type") == "srv_challenge") {
      std::string nn = "srv" + std::to_string(++n);
      nonces.insert(nn);
      return j(200, {{"Nonce", nn}});
    }
    if (revoked) return err(403, "forbidden");
    if (f.at("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || f.at("platform_sso_version") != "1.0") return err(400, "unsupported_grant_type");
    std::string jwt = f.at("assertion");
    json h = jsonSeg(jwt, 0), b = jsonSeg(jwt, 1);
    if (h["alg"] != "ES256" || h["kid"] != jwkKid(signingPub)) return err(401, "unknown_device");
    if (!sigOk(signingPub, seg(jwt, 0) + "." + seg(jwt, 1), seg(jwt, 2))) return err(401, "bad_signature");
    if (b["client_id"] != "pk_1" || b["iss"] != "pk_1" || b["aud"] != tokenEndpoint) return err(401, "bad_claims");
    if (!nonces.erase(b["request_nonce"])) return err(401, "nonce");
    bool isLogin = b["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer";
    bool isRefresh = b["grant_type"] == "refresh_token";
    if (isLogin) {
      if (h["typ"] != "platformsso-login-request+jwt") return err(400, "typ");
      std::string emb = b["assertion"];
      json eh = jsonSeg(emb, 0), eb = jsonSeg(emb, 1);
      if (eh["kid"] != jwkKid(userPub) || !sigOk(userPub, seg(emb, 0) + "." + seg(emb, 1), seg(emb, 2))) return err(401, "bad_assertion");
      if (eb["nonce"] != b["nonce"] || eb["request_nonce"] != b["request_nonce"] || eb["scope"] != b["scope"] || eb["aud"] != kBase || eb["sub"] != b["sub"])
        return err(401, "assertion_mismatch");
    } else if (isRefresh) {
      if (h["typ"] != "platformsso-refresh-request+jwt") return err(400, "typ");
      if (b["refresh_token"] != refreshToken) { refreshToken.clear(); revoked = true; return err(401, "invalid_grant"); }  // reuse kills the family
    } else {
      return err(400, "unsupported_grant_type");
    }
    refreshToken = "rt" + std::to_string(++refreshN);
    json claims = {{"iss", kBase}, {"aud", "pk_1"}, {"sub", "usr_1"}, {"exp", 4000000000LL}, {"nonce", b["nonce"]}, {"dsr", regId}};
    if (badIdToken) claims["aud"] = "other";
    std::string idt = jwsSignEs256(*instanceKey, {{"typ", "JWT"}, {"alg", "ES256"}, {"kid", "ik"}}, claims);
    Bytes apv = *b64uDecode(b["jwe_crypto"]["apv"]);
    std::string jwe = jweSealEcdhEs(*eph, encPub, {{"id_token", idt}, {"refresh_token", refreshToken}, {"token_type", "Bearer"}, {"expires_in", 28800}, {"refresh_token_expires_in", 2592000}}, apv);
    return {200, jwe};
  }
};

struct Rig {
  Idp idp;
  std::unique_ptr<SoftwareDeviceKey> signing = SoftwareDeviceKey::generate(), enc = SoftwareDeviceKey::generate(), user = SoftwareDeviceKey::generate();
  MemorySecretStore store;
  t::TestClock clock;
  SsoClient client{kBase, "pk_1", *signing, *enc, *user, idp, store, clock};
  Rig() { clock.now = 1800000000000; }
  void registerAll() {
    ASSERT_TRUE(client.fetchConfiguration().ok);
    ASSERT_TRUE(client.registerDevice("dsk_abc", "PC-1", "windows", "0.2.0").ok);
    ASSERT_TRUE(client.registerUser("alice", "user_tpm_key").ok);
  }
};
}  // namespace

TEST(SsoFlow, RegisterLoginRefreshAndWebSession) {
  Rig r;
  r.registerAll();
  EXPECT_EQ(r.client.state().registrationId, "dsso_1");
  SsoResult l = r.client.login();
  ASSERT_TRUE(l.ok) << l.error;
  EXPECT_EQ(r.client.state().refreshToken, "rt1");
  EXPECT_EQ(r.client.state().userId, "usr_1");
  ASSERT_TRUE(r.client.refresh().ok);
  EXPECT_EQ(r.client.state().refreshToken, "rt2");  // rotated
  std::string url;
  ASSERT_TRUE(r.client.webSession(url).ok);
  EXPECT_EQ(url, "https://auth.example.com/v1/client/sign_in?ticket=t1");
}

TEST(SsoFlow, ReusedRefreshTokenKillsTheFamilyAndTheClientDropsIt) {
  Rig r;
  r.registerAll();
  ASSERT_TRUE(r.client.login().ok);
  SsoState s = r.client.state();
  r.idp.refreshToken = "rt-other";  // someone else rotated it
  SsoResult res = r.client.refresh();
  EXPECT_FALSE(res.ok);
  EXPECT_TRUE(r.client.state().refreshToken.empty());
  EXPECT_FALSE(r.client.refresh().ok);
  (void)s;
}

TEST(SsoFlow, WebSessionNeedsALiveSessionAndRefreshNeedsOneToo) {
  Rig r;
  r.registerAll();
  std::string url;
  EXPECT_EQ(r.client.webSession(url).error, "no_session");  // never logged in
  ASSERT_TRUE(r.client.login().ok);
  r.clock.now += 9 * 3600 * 1000;  // past session_expires_at (8 h)
  EXPECT_EQ(r.client.webSession(url).error, "no_session");
  r.clock.now += 31LL * 24 * 3600 * 1000;
  EXPECT_EQ(r.client.refresh().error, "session_expired");
}

TEST(SsoFlow, RevokedRegistrationIsReportedAsRevoked) {
  Rig r;
  r.registerAll();
  r.idp.revoked = true;
  EXPECT_EQ(r.client.login().error, "revoked");
}

TEST(SsoFlow, ConfigurationIsRefusedWhenOffOrPointingElsewhere) {
  Rig r;
  r.idp.enabled = false;
  EXPECT_EQ(r.client.fetchConfiguration().error, "not_enabled");
  r.idp.enabled = true;
  r.idp.tokenEndpoint = "https://evil.example.net/v1/client/device_sso/token";  // signed requests must stay on the instance
  EXPECT_EQ(r.client.fetchConfiguration().error, "bad_configuration");
}

TEST(SsoFlow, ForgedIdTokenFailsLogin) {
  Rig r;
  r.registerAll();
  r.idp.badIdToken = true;
  EXPECT_EQ(r.client.login().error, "id_token_invalid");
  EXPECT_TRUE(r.client.state().refreshToken.empty());  // nothing is kept from an answer we could not verify
}

TEST(SsoFlow, WrongOrReusedRegistrationCodeIsRejected) {
  Rig r;
  ASSERT_TRUE(r.client.fetchConfiguration().ok);
  EXPECT_EQ(r.client.registerDevice("dsk_wrong", "PC", "windows", "1").error, "rejected:verification_failed");
  EXPECT_TRUE(r.client.registerDevice("dsk_abc", "PC", "windows", "1").ok);
  EXPECT_FALSE(r.client.registerDevice("dsk_abc", "PC", "windows", "1").ok);
}

TEST(SsoFlow, LoginBeforeRegistrationIsRefusedLocally) {
  Rig r;
  ASSERT_TRUE(r.client.fetchConfiguration().ok);
  EXPECT_EQ(r.client.login().error, "not_registered");
}
