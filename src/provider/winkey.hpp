// Device keys in CNG, machine scope, non-exportable. Two separate keys (a TPM cannot do both jobs in one key):
//   Signing: ECDSA_P256, ES256 signatures.   Seal: ECDH_P256, opens the offline bundles.
// Each prefers the TPM ("Microsoft Platform Crypto Provider") and falls back to the software KSP.
#pragma once
#include "atlas/base.hpp"

#include <windows.h>
#include <ncrypt.h>

#include <memory>
#include <string>

namespace win {

enum class KeyKind { Signing, Seal };

// NCryptDeriveKey(BCRYPT_KDF_RAW_SECRET) returns the shared secret in the byte order CNG uses internally
// (little endian). The protocol (and OpenSSL) use the big-endian X coordinate. This is the ONE place that converts;
// tests/windows/ncrypt_ecdh_test.cpp pins it against OpenSSL on a real CNG, so a wrong assumption fails CI.
atlas::Bytes cngRawSecretToBigEndian(const atlas::Bytes& raw);

class CngDeviceKey : public atlas::IDeviceKey, public atlas::ISealKey {
 public:
  static std::unique_ptr<CngDeviceKey> open(const std::wstring& name);
  // Replaces any key of that name. `hardware` reports whether the TPM provider holds it.
  static std::unique_ptr<CngDeviceKey> create(const std::wstring& name, KeyKind kind, bool& hardware, std::string& err);
  ~CngDeviceKey() override;
  CngDeviceKey(const CngDeviceKey&) = delete;
  CngDeviceKey& operator=(const CngDeviceKey&) = delete;

  atlas::Bytes sign(const atlas::Bytes& message) override;  // Signing keys only
  atlas::Bytes ecdh(const atlas::Bytes& peerUncompressedPoint) override;  // Seal keys only
  atlas::json publicJwk() override;
  // Raw NCryptDeriveKey output (see cngRawSecretToBigEndian). Seal keys only.
  atlas::Bytes ecdhRaw(const atlas::Bytes& peerUncompressedPoint);
  // Test support: an in-memory (non-persisted) software ECDH P-256 key from big-endian x, y, d.
  static std::unique_ptr<CngDeviceKey> importEphemeralEcdh(const atlas::Bytes& x, const atlas::Bytes& y, const atlas::Bytes& d);
  void deleteKey();  // used by the enrolment tool when enrolment fails

 private:
  CngDeviceKey(NCRYPT_PROV_HANDLE p, NCRYPT_KEY_HANDLE k) : prov_(p), key_(k) {}
  NCRYPT_PROV_HANDLE prov_;
  NCRYPT_KEY_HANDLE key_;
};

}  // namespace win
