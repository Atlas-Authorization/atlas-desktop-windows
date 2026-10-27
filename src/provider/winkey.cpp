#include "winkey.hpp"

#include <bcrypt.h>

#include <algorithm>

namespace win {
using atlas::Bytes;

namespace {
const wchar_t* kProviders[] = {MS_PLATFORM_CRYPTO_PROVIDER, MS_KEY_STORAGE_PROVIDER};
const DWORD kMachine = NCRYPT_MACHINE_KEY_FLAG;
}  // namespace

std::unique_ptr<CngDeviceKey> CngDeviceKey::open(const std::wstring& name) {
  for (const wchar_t* prov : kProviders) {
    NCRYPT_PROV_HANDLE p = 0;
    if (NCryptOpenStorageProvider(&p, prov, 0) != ERROR_SUCCESS) continue;
    NCRYPT_KEY_HANDLE k = 0;
    if (NCryptOpenKey(p, &k, name.c_str(), 0, kMachine) == ERROR_SUCCESS)
      return std::unique_ptr<CngDeviceKey>(new CngDeviceKey(p, k));
    NCryptFreeObject(p);
  }
  return nullptr;
}

std::unique_ptr<CngDeviceKey> CngDeviceKey::create(const std::wstring& name, KeyKind kind, bool& hardware, std::string& err) {
  hardware = false;
  for (const wchar_t* prov : kProviders) {
    NCRYPT_PROV_HANDLE p = 0;
    if (NCryptOpenStorageProvider(&p, prov, 0) != ERROR_SUCCESS) continue;
    NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS st = NCryptCreatePersistedKey(p, &k, kind == KeyKind::Signing ? BCRYPT_ECDSA_P256_ALGORITHM : BCRYPT_ECDH_P256_ALGORITHM, name.c_str(), 0,
                                                  kMachine | NCRYPT_OVERWRITE_KEY_FLAG);
    if (st == ERROR_SUCCESS) {
      DWORD usage = kind == KeyKind::Signing ? NCRYPT_ALLOW_SIGNING_FLAG : NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;
      st = NCryptSetProperty(k, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&usage), sizeof usage,
                             NCRYPT_PERSIST_FLAG);
      if (st == ERROR_SUCCESS) st = NCryptFinalizeKey(k, 0);
      if (st == ERROR_SUCCESS) {
        hardware = std::wstring(prov) == MS_PLATFORM_CRYPTO_PROVIDER;
        return std::unique_ptr<CngDeviceKey>(new CngDeviceKey(p, k));
      }
      NCryptDeleteKey(k, 0);
    }
    err = "CNG error 0x" + std::to_string(static_cast<unsigned long>(st));
    NCryptFreeObject(p);
  }
  return nullptr;
}

CngDeviceKey::~CngDeviceKey() {
  if (key_) NCryptFreeObject(key_);
  if (prov_) NCryptFreeObject(prov_);
}

void CngDeviceKey::deleteKey() {
  if (key_) { NCryptDeleteKey(key_, 0); key_ = 0; }  // frees the handle
}

Bytes CngDeviceKey::sign(const Bytes& message) {
  if (!key_) return {};
  Bytes hash = atlas::sha256(message);
  Bytes sig(64);
  DWORD n = 0;
  // ECDSA output from CNG is already IEEE P1363 (r||s), 32 bytes each.
  if (NCryptSignHash(key_, nullptr, hash.data(), static_cast<DWORD>(hash.size()), sig.data(), static_cast<DWORD>(sig.size()),
                     &n, 0) != ERROR_SUCCESS || n != 64)
    return {};
  return sig;
}

Bytes cngRawSecretToBigEndian(const Bytes& raw) {
  return Bytes(raw.rbegin(), raw.rend());
}

Bytes CngDeviceKey::ecdh(const Bytes& peer) { return cngRawSecretToBigEndian(ecdhRaw(peer)); }

std::unique_ptr<CngDeviceKey> CngDeviceKey::importEphemeralEcdh(const Bytes& x, const Bytes& y, const Bytes& d) {
  if (x.size() != 32 || y.size() != 32 || d.size() != 32) return nullptr;
  NCRYPT_PROV_HANDLE p = 0;
  if (NCryptOpenStorageProvider(&p, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) return nullptr;
  Bytes blob(sizeof(BCRYPT_ECCKEY_BLOB) + 96);
  auto* h = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
  h->dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
  h->cbKey = 32;
  uint8_t* at = blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
  std::copy(x.begin(), x.end(), at);
  std::copy(y.begin(), y.end(), at + 32);
  std::copy(d.begin(), d.end(), at + 64);
  NCRYPT_KEY_HANDLE k = 0;
  if (NCryptImportKey(p, 0, BCRYPT_ECCPRIVATE_BLOB, nullptr, &k, blob.data(), static_cast<DWORD>(blob.size()), 0) != ERROR_SUCCESS) {
    NCryptFreeObject(p);
    return nullptr;
  }
  return std::unique_ptr<CngDeviceKey>(new CngDeviceKey(p, k));
}

Bytes CngDeviceKey::ecdhRaw(const Bytes& peer) {
  if (!key_ || peer.size() != 65 || peer[0] != 0x04) return {};
  Bytes blob(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
  auto* h = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
  h->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
  h->cbKey = 32;
  std::copy(peer.begin() + 1, peer.end(), blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB));
  NCRYPT_KEY_HANDLE peerKey = 0;
  NCRYPT_SECRET_HANDLE secret = 0;
  Bytes out;
  if (NCryptImportKey(prov_, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, &peerKey, blob.data(), static_cast<DWORD>(blob.size()), 0) ==
          ERROR_SUCCESS &&
      NCryptSecretAgreement(key_, peerKey, &secret, 0) == ERROR_SUCCESS) {
    Bytes raw(32);
    DWORD n = 0;
    if (NCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, nullptr, raw.data(), static_cast<DWORD>(raw.size()), &n, 0) ==
            ERROR_SUCCESS &&
        n == 32) {
      out = raw;
    }
  }
  if (secret) NCryptFreeObject(secret);
  if (peerKey) NCryptFreeObject(peerKey);
  return out;
}

atlas::json CngDeviceKey::publicJwk() {
  DWORD n = 0;
  if (!key_ || NCryptExportKey(key_, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &n, 0) != ERROR_SUCCESS)
    return atlas::json::object();
  Bytes blob(n);
  if (NCryptExportKey(key_, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(), n, &n, 0) != ERROR_SUCCESS ||
      n != sizeof(BCRYPT_ECCKEY_BLOB) + 64)
    return atlas::json::object();
  const uint8_t* xy = blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
  return {{"kty", "EC"}, {"crv", "P-256"}, {"x", atlas::b64uEncode(Bytes(xy, xy + 32))}, {"y", atlas::b64uEncode(Bytes(xy + 32, xy + 64))}};
}

}  // namespace win
