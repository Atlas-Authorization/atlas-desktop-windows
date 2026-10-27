// Windows only. Pins the CNG ECDH behaviour against OpenSSL and the server's real sealed bundle, instead of
// trusting memory about NCryptDeriveKey(BCRYPT_KDF_RAW_SECRET) byte order.
#include <gtest/gtest.h>

#include "../fixture.hpp"
#include "winkey.hpp"

using namespace atlas;

namespace {
Bytes pointOf(const json& jwk) {
  Bytes p{0x04};
  for (const char* c : {"x", "y"}) {
    auto d = *b64uDecode(jwk[c].get<std::string>());
    p.insert(p.end(), d.begin(), d.end());
  }
  return p;
}
std::string hex(const Bytes& b) {
  static const char* d = "0123456789abcdef";
  std::string o;
  for (uint8_t c : b) { o += d[c >> 4]; o += d[c & 15]; }
  return o;
}
struct TempKey {
  std::unique_ptr<win::CngDeviceKey> key;
  explicit TempKey(const wchar_t* name) {
    bool hw = false;
    std::string err;
    key = win::CngDeviceKey::create(name, win::KeyKind::Seal, hw, err);
  }
  ~TempKey() { if (key) key->deleteKey(); }
};
}  // namespace

TEST(CngEcdh, SharedSecretMatchesOpenSsl) {
  TempKey cng(L"AtlasLoginAgentTest-ecdh");
  ASSERT_TRUE(cng.key) << "could not create a CNG ECDH_P256 key";
  auto peer = SoftwareDeviceKey::generate();
  ASSERT_TRUE(peer);

  Bytes cngPoint = pointOf(cng.key->publicJwk());
  Bytes fromOpenSsl = peer->ecdh(cngPoint);  // OpenSSL: peer private x CNG public
  ASSERT_EQ(fromOpenSsl.size(), 32u);

  Bytes raw = cng.key->ecdhRaw(pointOf(peer->publicJwk()));  // CNG: CNG private x OpenSSL public
  ASSERT_EQ(raw.size(), 32u);
  Bytes reversed(raw.rbegin(), raw.rend());
  // Empirical record for the log: which byte order did NCryptDeriveKey(RAW_SECRET) return?
  RecordProperty("raw_equals_openssl", raw == fromOpenSsl ? "yes" : "no");
  RecordProperty("reversed_equals_openssl", reversed == fromOpenSsl ? "yes" : "no");
  std::cout << "raw      " << hex(raw) << "\nreversed " << hex(reversed) << "\nopenssl  " << hex(fromOpenSsl) << "\n";

  EXPECT_EQ(win::cngRawSecretToBigEndian(raw), fromOpenSsl) << "winkey.cpp's byte-order helper is wrong";
  EXPECT_EQ(cng.key->ecdh(pointOf(peer->publicJwk())), fromOpenSsl);
}

TEST(CngEcdh, OpensServerSealedBundleThroughCng) {
  const json& priv = t::vectors()["device_private_jwk"];
  auto key = win::CngDeviceKey::importEphemeralEcdh(*b64uDecode(priv["x"].get<std::string>()),
                                                    *b64uDecode(priv["y"].get<std::string>()),
                                                    *b64uDecode(priv["d"].get<std::string>()));
  ASSERT_TRUE(key) << "could not import the vector key as a CNG ECDH key";
  EXPECT_EQ(key->publicJwk()["x"], t::vectors()["device_public_jwk"]["x"]);
  EXPECT_EQ(key->publicJwk()["y"], t::vectors()["device_public_jwk"]["y"]);

  auto plain = openBundle(*key, t::vectors()["bundle"]["sealed"]);
  ASSERT_TRUE(plain) << "the CNG ECDH path could not open the server's sealed bundle";
  const json& pl = t::vectors()["bundle"]["plaintext"];
  EXPECT_EQ(plain->bundleId, pl["bundle_id"]);
  EXPECT_EQ(plain->deviceId, pl["device_id"]);
  EXPECT_EQ(plain->totp.secret, pl["totp"]["secret"]);
  ASSERT_TRUE(plain->pin);
  EXPECT_EQ(plain->pin->hash, pl["pin"]["hash"]);
}

TEST(CngEcdh, SignatureFromCngSigningKeyVerifies) {
  bool hw = false;
  std::string err;
  auto k = win::CngDeviceKey::create(L"AtlasLoginAgentTest-sign", win::KeyKind::Signing, hw, err);
  ASSERT_TRUE(k) << err;
  Bytes msg = toBytes("atlas-desktop:v1:sync:ins:ddv:n:-");
  Bytes sig = k->sign(msg);
  ASSERT_EQ(sig.size(), 64u);
  EXPECT_TRUE(ecdsaVerifyP1363(k->publicJwk(), msg, sig));
  k->deleteKey();
}
