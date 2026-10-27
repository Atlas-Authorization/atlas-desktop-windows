#include "atlas/softkey.hpp"

#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "crypto_internal.hpp"

namespace atlas {
using detail::EvpPkey;

std::unique_ptr<SoftwareDeviceKey> SoftwareDeviceKey::generate() {
  EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
  if (!k) return nullptr;
  return std::unique_ptr<SoftwareDeviceKey>(new SoftwareDeviceKey(EvpPkey(k, EVP_PKEY_free)));
}

std::unique_ptr<SoftwareDeviceKey> SoftwareDeviceKey::fromPrivateJwk(const json& jwk) {
  auto pt = detail::pointFromJwk(jwk);
  auto d = b64uDecode(jwk.value("d", ""));
  if (!pt || !d || d->size() != 32) return nullptr;
  auto k = detail::pkeyFromPoint(*pt, &*d);
  if (!k) return nullptr;
  return std::unique_ptr<SoftwareDeviceKey>(new SoftwareDeviceKey(k));
}

Bytes SoftwareDeviceKey::sign(const Bytes& message) {
  EVP_MD_CTX* md = EVP_MD_CTX_new();
  Bytes der;
  size_t n = 0;
  if (md && EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, key_.get()) == 1 &&
      EVP_DigestSign(md, nullptr, &n, message.data(), message.size()) == 1) {
    der.resize(n);
    if (EVP_DigestSign(md, der.data(), &n, message.data(), message.size()) == 1) der.resize(n);
    else der.clear();
  }
  EVP_MD_CTX_free(md);
  return der.empty() ? Bytes() : detail::derToP1363(der);
}

Bytes SoftwareDeviceKey::ecdh(const Bytes& peer) {
  auto pk = detail::pkeyFromPoint(peer, nullptr);
  if (!pk) return {};
  EVP_PKEY_CTX* c = EVP_PKEY_CTX_new(key_.get(), nullptr);
  Bytes out;
  size_t n = 0;
  if (c && EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, pk.get()) == 1 &&
      EVP_PKEY_derive(c, nullptr, &n) == 1) {
    out.resize(n);
    if (EVP_PKEY_derive(c, out.data(), &n) != 1) out.clear();
    else out.resize(n);
  }
  EVP_PKEY_CTX_free(c);
  return out;
}

json SoftwareDeviceKey::publicJwk() {
  uint8_t buf[65];
  size_t len = 0;
  if (EVP_PKEY_get_octet_string_param(key_.get(), OSSL_PKEY_PARAM_PUB_KEY, buf, sizeof buf, &len) != 1 || len != 65)
    return json::object();
  Bytes x(buf + 1, buf + 33), y(buf + 33, buf + 65);
  return json{{"kty", "EC"}, {"crv", "P-256"}, {"x", b64uEncode(x)}, {"y", b64uEncode(y)}};
}

}  // namespace atlas
