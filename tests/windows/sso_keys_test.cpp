// Windows only. The per-user CNG keys the SSO broker uses, through the real CNG (software key store on a CI runner: no TPM).
// Nothing here signs with a presence key: that would raise a consent dialog nobody can answer on a runner.
#include <gtest/gtest.h>

#include <cstdlib>

#include "../fixture.hpp"
#include "atlas/devicesso.hpp"
#include "winkey.hpp"

using namespace atlas;

namespace {
struct Temp {
  std::unique_ptr<win::CngDeviceKey> key;
  bool hardware = false;
  std::string err;
  Temp(const wchar_t* name, win::KeyKind kind, bool presence) {
    key = win::CngDeviceKey::create(name, kind, hardware, err, win::KeyScope::User, presence);
  }
  ~Temp() { if (key) key->deleteKey(); }
};
Bytes pointOf(const json& jwk) {
  Bytes p{0x04};
  for (const char* c : {"x", "y"}) {
    auto d = *b64uDecode(jwk[c].get<std::string>());
    p.insert(p.end(), d.begin(), d.end());
  }
  return p;
}
}  // namespace

TEST(SsoKeys, UserScopeSigningKeySignsInIeeeP1363AndHasAnAppleKid) {
  Temp t(L"AtlasSsoTest-sign", win::KeyKind::Signing, false);
  ASSERT_TRUE(t.key) << t.err;
  Bytes msg = toBytes("atlas-desktop:v1:sso_web:ins:dsso_1:nonce");
  Bytes sig = t.key->sign(msg);
  ASSERT_EQ(sig.size(), 64u);
  EXPECT_TRUE(ecdsaVerifyP1363(t.key->publicJwk(), msg, sig));
  EXPECT_EQ(jwkKid(t.key->publicJwk()).size(), 44u);  // base64 of 32 bytes, padded
  auto again = win::CngDeviceKey::open(L"AtlasSsoTest-sign", win::KeyScope::User);
  ASSERT_TRUE(again);
  EXPECT_EQ(again->publicJwk(), t.key->publicJwk());
  EXPECT_FALSE(win::CngDeviceKey::open(L"AtlasSsoTest-sign", win::KeyScope::Machine));  // a user key is not a machine key
}

TEST(SsoKeys, JweSealedToACngEncryptionKeyOpens) {
  Temp t(L"AtlasSsoTest-enc", win::KeyKind::Seal, false);
  ASSERT_TRUE(t.key) << t.err;
  auto eph = SoftwareDeviceKey::generate();
  Bytes apv = applePartyVInfo(pointOf(t.key->publicJwk()), "n1");
  std::string jwe = jweSealEcdhEs(*eph, t.key->publicJwk(), {{"refresh_token", "r"}}, apv);
  auto open = jweOpenEcdhEs(*t.key, jwe, apv);  // CNG's secret byte order is the thing under test
  ASSERT_TRUE(open);
  EXPECT_EQ((*open)["refresh_token"], "r");
}

TEST(SsoKeys, PresenceKeyIsCreatedOnlyWhereTheProviderCanAskForPresence) {
  // Finalizing a UI-protected key can raise a consent dialog nobody can answer on a runner (it hung CI for hours): opt in only.
  if (!std::getenv("ATLAS_TEST_INTERACTIVE")) GTEST_SKIP() << "set ATLAS_TEST_INTERACTIVE=1 on a desktop session to run";
  Temp t(L"AtlasSsoTest-user", win::KeyKind::Signing, true);
  ASSERT_TRUE(t.key) << t.err;
  std::printf("presence key provider: %s\n", t.hardware ? "TPM" : "software key store");
  EXPECT_EQ(t.key->publicJwk().value("crv", ""), "P-256");
}
