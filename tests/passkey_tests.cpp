#include <gtest/gtest.h>

#include "atlas/passkey.hpp"

using namespace atlas;

namespace {
json base() {
  return {{"challenge", "QUJDREVGR0hJSktMTU5PUA"}, {"rpId", "auth.example.com"}, {"origin", "https://auth.example.com"}};
}
json creation() {
  return {{"challenge", "QUJDREVGR0hJSktMTU5PUA"}, {"rp", {{"id", "auth.example.com"}, {"name", "Atlas"}}}, {"origin", "https://auth.example.com"},
          {"user", {{"id", "dXNyXzE"}, {"name", "u"}, {"displayName", "U"}}},
          {"pubKeyCredParams", json::array({{{"type", "public-key"}, {"alg", -7}}, {{"type", "public-key"}, {"alg", -257}}})},
          {"excludeCredentials", json::array({{{"type", "public-key"}, {"id", "AQID"}}})},
          {"authenticatorSelection", {{"userVerification", "required"}}}, {"timeout", 5}};
}
}  // namespace

TEST(PasskeyParse, AcceptsTheServersOptions) {
  json o = base();
  o["userVerification"] = "required";
  o["timeout"] = 60000;
  o["allowCredentials"] = json::array({{{"type", "public-key"}, {"id", "AQID"}, {"transports", json::array({"usb", "nfc"})}}});
  std::string err;
  auto r = parsePasskeyRequest(o, err);
  ASSERT_TRUE(r) << err;
  EXPECT_EQ(r->rpId, "auth.example.com");
  EXPECT_EQ(r->userVerification, "required");
  ASSERT_EQ(r->allow.size(), 1u);
  EXPECT_EQ(r->allow[0].id, (Bytes{1, 2, 3}));
  EXPECT_EQ(r->allow[0].transports, (std::vector<std::string>{"usb", "nfc"}));
  EXPECT_EQ(r->timeoutMs, 60000u);
}

TEST(PasskeyParse, OriginMustBeExactlyHttpsRpId) {
  std::string err;
  for (const char* bad : {"http://auth.example.com", "https://auth.example.com:8443", "https://evil.example", "https://x.auth.example.com",
                          "https://auth.example.com/", "", "auth.example.com"}) {
    json o = base();
    o["origin"] = bad;
    EXPECT_FALSE(parsePasskeyRequest(o, err)) << bad;
  }
  json o = base();
  o["rpId"] = "";
  o["origin"] = "https://";
  EXPECT_FALSE(parsePasskeyRequest(o, err));
}

TEST(PasskeyParse, RejectsMalformedFieldsAndClampsTimeout) {
  std::string err;
  EXPECT_FALSE(parsePasskeyRequest(json::array(), err));
  json o = base();
  o["challenge"] = "AAAA";  // 3 bytes: below the 16-byte floor
  EXPECT_FALSE(parsePasskeyRequest(o, err));
  o = base();
  o["challenge"] = "QUJD=REVGR0hJSktMTU5PUA";  // padding / foreign character
  EXPECT_FALSE(parsePasskeyRequest(o, err));
  o = base();
  o["userVerification"] = "sometimes";
  EXPECT_FALSE(parsePasskeyRequest(o, err));
  o = base();
  o["allowCredentials"] = "x";
  EXPECT_FALSE(parsePasskeyRequest(o, err));
  o = base();
  o["allowCredentials"] = json::array({{{"type", "public-key"}, {"id", "!!"}}});
  EXPECT_FALSE(parsePasskeyRequest(o, err));
  o = base();
  o["timeout"] = 1;
  EXPECT_EQ(parsePasskeyRequest(o, err)->timeoutMs, 10000u);
  o["timeout"] = 99999999;
  EXPECT_EQ(parsePasskeyRequest(o, err)->timeoutMs, 120000u);
  o.erase("timeout");
  EXPECT_EQ(parsePasskeyRequest(o, err)->timeoutMs, 60000u);
}

TEST(PasskeyParse, CreationOptions) {
  std::string err;
  auto c = parsePasskeyCreation(creation(), err);
  ASSERT_TRUE(c) << err;
  EXPECT_EQ(c->rpId, "auth.example.com");
  EXPECT_EQ(c->userId, toBytes("usr_1"));
  EXPECT_EQ(c->algorithms, (std::vector<int>{-7, -257}));
  ASSERT_EQ(c->exclude.size(), 1u);
  EXPECT_EQ(c->userVerification, "required");
  EXPECT_EQ(c->timeoutMs, 10000u);

  json o = creation();
  o["origin"] = "https://evil.example";
  EXPECT_FALSE(parsePasskeyCreation(o, err));
  o = creation();
  o["pubKeyCredParams"] = json::array();
  EXPECT_FALSE(parsePasskeyCreation(o, err));
  o = creation();
  o.erase("rp");
  EXPECT_FALSE(parsePasskeyCreation(o, err));
  o = creation();
  o["user"]["name"] = "";
  EXPECT_FALSE(parsePasskeyCreation(o, err));
}

TEST(PasskeyShapes, ClientDataAndPayloads) {
  json cd = json::parse(clientDataJson("webauthn.get", "chal", "https://auth.example.com"));
  EXPECT_EQ(cd, (json{{"type", "webauthn.get"}, {"challenge", "chal"}, {"origin", "https://auth.example.com"}, {"crossOrigin", false}}));
  json a = assertionJson("{}", "chal", RawAssertion{{1}, {2, 3}, {4}});
  EXPECT_EQ(a["credential_id"], "AQ");
  EXPECT_EQ(a["authenticator_data"], "AgM");
  EXPECT_EQ(a["signature"], "BA");
  EXPECT_EQ(a["client_data_json"], "e30");
  EXPECT_EQ(a["challenge"], "chal");
  json c = credentialJson("{}", "chal", RawAttestation{{1}, {9}, {}});
  EXPECT_EQ(c["attestation_object"], "CQ");
  EXPECT_FALSE(c.contains("signature"));
}
