// Device key in CNG: TPM ("Microsoft Platform Crypto Provider") when it accepts a sign+key-agreement key,
// otherwise the software KSP. Machine-scope, non-exportable.
#pragma once
#include "atlas/base.hpp"

#include <windows.h>
#include <ncrypt.h>

#include <memory>
#include <string>

namespace win {

class CngDeviceKey : public atlas::IDeviceKey {
 public:
  static std::unique_ptr<CngDeviceKey> open(const std::wstring& name);
  // Replaces any key of that name. `hardware` reports whether the TPM provider holds it.
  static std::unique_ptr<CngDeviceKey> create(const std::wstring& name, bool& hardware, std::string& err);
  ~CngDeviceKey() override;
  CngDeviceKey(const CngDeviceKey&) = delete;
  CngDeviceKey& operator=(const CngDeviceKey&) = delete;

  atlas::Bytes sign(const atlas::Bytes& message) override;
  atlas::Bytes ecdh(const atlas::Bytes& peerUncompressedPoint) override;
  atlas::json publicJwk() override;
  void deleteKey();  // used by the enrolment tool when enrolment fails

 private:
  CngDeviceKey(NCRYPT_PROV_HANDLE p, NCRYPT_KEY_HANDLE k) : prov_(p), key_(k) {}
  NCRYPT_PROV_HANDLE prov_;
  NCRYPT_KEY_HANDLE key_;
};

}  // namespace win
