#include <gtest/gtest.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "atlas/devicesso.hpp"
#include "atlas/softkey.hpp"
#include "../src/core/crypto_internal.hpp"

using namespace atlas;

namespace {
Bytes hex(const std::string& h) {
  Bytes o;
  for (size_t i = 0; i + 1 < h.size(); i += 2) o.push_back(static_cast<uint8_t>(std::stoi(h.substr(i, 2), nullptr, 16)));
  return o;
}
std::string split(const std::string& s, int idx) {
  size_t a = 0;
  for (int i = 0; i < idx; i++) a = s.find('.', a) + 1;
  size_t b = s.find('.', a);
  return s.substr(a, b == std::string::npos ? std::string::npos : b - a);
}
}  // namespace

// Apple, "Creating a JSON Web Encryption (JWE) login response": Concat KDF inputs and result.
TEST(DeviceSso, ConcatKdfMatchesApplesPublishedVector) {
  Bytes z = hex("3491708C92422BB807EDF2B8183A42737C5DAA6C39BA9535321D51C836D7ADA1");
  Bytes apu = hex("000000054150504C45000000410406414745842895EAB7F4BA651AA95C9AC11D9F0EB8C34C1B71B1C0123ACCE29C8DB3A85996E00C54C47CB6B53BFED9B89CB747C7765C0C340875942A624BB1B5");
  Bytes apv = hex("000000054170706C65000000410499C272AF606A5101E5B1C686A164F0FF840DC4352A235951D75902440CCB26493FF98BB592A830C0B71BC3ED46578ACE6D5CE43D1A7CF657FFAD6CEF40B1EF920000002442374631464333322D393132312D344532412D394533322D383431374530333637354444");
  EXPECT_EQ(concatKdf(z, "A256GCM", apu, apv, 256), hex("A146E4A23BDA2E53826C04D2F442BCFBD87BC2719D74B8A7DA00AF976267712E"));
}

TEST(DeviceSso, ApplePartyVInfoBuildsTheDocumentedLayout) {
  // "Final partyVInfo": len||"Apple" len||device encryption key len||nonce
  Bytes point = hex("0499C272AF606A5101E5B1C686A164F0FF840DC4352A235951D75902440CCB26493FF98BB592A830C0B71BC3ED46578ACE6D5CE43D1A7CF657FFAD6CEF40B1EF92");
  EXPECT_EQ(applePartyVInfo(point, "B7F1FC32-9121-4E2A-9E32-8417E03675DD"),
            hex("000000054170706C65000000410499C272AF606A5101E5B1C686A164F0FF840DC4352A235951D75902440CCB26493FF98BB592A830C0B71BC3ED46578ACE6D5CE43D1A7CF657FFAD6CEF40B1EF920000002442374631464333322D393132312D344532412D394533322D383431374530333637354444"));
}

// Apple, "Performing encryption verification": the device signing key and its kid.
TEST(DeviceSso, KidIsBase64OfSha256OfTheX963Point) {
  json jwk = {{"kty", "EC"}, {"crv", "P-256"}, {"x", "gK60EgxT-EipyAgSlrHG0LgFVrgnd8UXAvLOgykJtms"}, {"y", "PAIz7YrH4Rxz1rlfn6JcnwSmFDVGY1ISlGnmK1NX5vs"}};
  EXPECT_EQ(jwkKid(jwk), "Ws9mKynZxyUSNXYtMGAjjLO+Jg16HCa/5pJO0udNWJ4=");
  EXPECT_EQ(jwkKid(json{{"kty", "RSA"}}), "");
}

TEST(DeviceSso, Es256JwsVerifiesAndCarriesTheHeader) {
  auto k = SoftwareDeviceKey::generate();
  std::string jws = jwsSignEs256(*k, {{"typ", "JWT"}, {"alg", "ES256"}, {"kid", "k"}}, {{"a", 1}});
  Bytes sig = *b64uDecode(split(jws, 2));
  EXPECT_EQ(sig.size(), 64u);
  EXPECT_TRUE(ecdsaVerifyP1363(k->publicJwk(), toBytes(split(jws, 0) + "." + split(jws, 1)), sig));
  EXPECT_EQ(json::parse(toString(*b64uDecode(split(jws, 0))))["kid"], "k");
}

TEST(DeviceSso, JweRoundTripAndEveryTamperFails) {
  auto device = SoftwareDeviceKey::generate();
  auto eph = SoftwareDeviceKey::generate();
  Bytes apv = applePartyVInfo(*detail::pointFromJwk(device->publicJwk()), "nonce-1");
  std::string jwe = jweSealEcdhEs(*eph, device->publicJwk(), {{"refresh_token", "r1"}, {"id_token", "i1"}}, apv);
  auto open = jweOpenEcdhEs(*device, jwe, apv);
  ASSERT_TRUE(open);
  EXPECT_EQ((*open)["refresh_token"], "r1");

  EXPECT_FALSE(jweOpenEcdhEs(*device, jwe, applePartyVInfo(*detail::pointFromJwk(device->publicJwk()), "nonce-2")));  // another request's answer
  EXPECT_FALSE(jweOpenEcdhEs(*eph, jwe, apv));                                                                         // wrong recipient
  std::string flipped = jwe;
  flipped[flipped.size() - 3] = flipped[flipped.size() - 3] == 'A' ? 'B' : 'A';  // tag
  EXPECT_FALSE(jweOpenEcdhEs(*device, flipped, apv));
  // header is the GCM AAD: change an (otherwise irrelevant) header member and the tag no longer matches
  json h = json::parse(toString(*b64uDecode(split(jwe, 0))));
  h["kid"] = "x";
  EXPECT_FALSE(jweOpenEcdhEs(*device, b64uEncode(h.dump()) + jwe.substr(jwe.find('.')), apv));
  EXPECT_FALSE(jweOpenEcdhEs(*device, "a.b.c", apv));
  h = json::parse(toString(*b64uDecode(split(jwe, 0))));
  h["enc"] = "A128GCM";
  EXPECT_FALSE(jweOpenEcdhEs(*device, b64uEncode(h.dump()) + jwe.substr(jwe.find('.')), apv));
}

namespace {
json es256Jwks(SoftwareDeviceKey& k, const std::string& kid) {
  json j = k.publicJwk();
  j["kid"] = kid;
  j["alg"] = "ES256";
  return {{"keys", json::array({j})}};
}
std::string idToken(SoftwareDeviceKey& k, const std::string& kid, json claims) {
  return jwsSignEs256(k, {{"typ", "JWT"}, {"alg", "ES256"}, {"kid", kid}}, claims);
}
}  // namespace

TEST(DeviceSso, IdTokenChecksSignatureIssuerAudienceNonceAndExpiry) {
  auto key = SoftwareDeviceKey::generate();
  auto other = SoftwareDeviceKey::generate();
  json jwks = es256Jwks(*key, "kid1");
  json claims = {{"iss", "https://auth.example.com"}, {"aud", "pk_1"}, {"exp", 2000}, {"nonce", "n1"}, {"sub", "usr_1"}};
  std::string tok = idToken(*key, "kid1", claims);
  EXPECT_TRUE(verifyIdToken(tok, jwks, "https://auth.example.com", "pk_1", "n1", 1000));
  EXPECT_FALSE(verifyIdToken(tok, jwks, "https://evil.example.com", "pk_1", "n1", 1000));
  EXPECT_FALSE(verifyIdToken(tok, jwks, "https://auth.example.com", "pk_2", "n1", 1000));
  EXPECT_FALSE(verifyIdToken(tok, jwks, "https://auth.example.com", "pk_1", "n2", 1000));
  EXPECT_FALSE(verifyIdToken(tok, jwks, "https://auth.example.com", "pk_1", "n1", 2061));  // expired beyond skew
  EXPECT_TRUE(verifyIdToken(tok, jwks, "https://auth.example.com", "pk_1", "n1", 2059));
  EXPECT_FALSE(verifyIdToken(idToken(*other, "kid1", claims), jwks, "https://auth.example.com", "pk_1", "n1", 1000));  // wrong key
  EXPECT_FALSE(verifyIdToken(idToken(*key, "kid9", claims), jwks, "https://auth.example.com", "pk_1", "n1", 1000));   // unknown kid
  // alg:none and HS256 are never accepted
  std::string none = b64uEncode(json{{"alg", "none"}, {"kid", "kid1"}}.dump()) + "." + split(tok, 1) + ".";
  EXPECT_FALSE(verifyIdToken(none, jwks, "https://auth.example.com", "pk_1", "n1", 1000));
  json aud = claims;
  aud["aud"] = json::array({"x", "pk_1"});
  EXPECT_TRUE(verifyIdToken(idToken(*key, "kid1", aud), jwks, "https://auth.example.com", "pk_1", "n1", 1000));
}

TEST(DeviceSso, IdTokenRs256) {
  EVP_PKEY* rsa = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<size_t>(2048));
  ASSERT_TRUE(rsa);
  auto bn = [&](const char* name) {
    BIGNUM* b = nullptr;
    EVP_PKEY_get_bn_param(rsa, name, &b);
    Bytes o(static_cast<size_t>(BN_num_bytes(b)));
    BN_bn2bin(b, o.data());
    BN_free(b);
    return o;
  };
  json jwks = {{"keys", json::array({{{"kty", "RSA"}, {"kid", "r1"}, {"alg", "RS256"}, {"n", b64uEncode(bn("n"))}, {"e", b64uEncode(bn("e"))}}})}};
  std::string input = b64uEncode(json{{"alg", "RS256"}, {"kid", "r1"}}.dump()) + "." +
                      b64uEncode(json{{"iss", "i"}, {"aud", "a"}, {"exp", 5000}, {"nonce", "n"}}.dump());
  EVP_MD_CTX* md = EVP_MD_CTX_new();
  size_t n = 0;
  ASSERT_EQ(EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, rsa), 1);
  ASSERT_EQ(EVP_DigestSign(md, nullptr, &n, reinterpret_cast<const unsigned char*>(input.data()), input.size()), 1);
  Bytes sig(n);
  ASSERT_EQ(EVP_DigestSign(md, sig.data(), &n, reinterpret_cast<const unsigned char*>(input.data()), input.size()), 1);
  EVP_MD_CTX_free(md);
  EVP_PKEY_free(rsa);
  EXPECT_TRUE(verifyIdToken(input + "." + b64uEncode(sig), jwks, "i", "a", "n", 1000));
  sig[5] ^= 1;
  EXPECT_FALSE(verifyIdToken(input + "." + b64uEncode(sig), jwks, "i", "a", "n", 1000));
}
