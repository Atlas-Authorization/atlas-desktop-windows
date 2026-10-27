// Software P-256 device key (OpenSSL). Used by tests; the Windows build uses a CNG/TPM key instead.
#pragma once
#include "atlas/base.hpp"

struct evp_pkey_st;

namespace atlas {

class SoftwareDeviceKey : public IDeviceKey {
 public:
  static std::unique_ptr<SoftwareDeviceKey> generate();
  // jwk must carry the private scalar `d`.
  static std::unique_ptr<SoftwareDeviceKey> fromPrivateJwk(const json& jwk);
  Bytes sign(const Bytes& message) override;
  Bytes ecdh(const Bytes& peerUncompressedPoint) override;
  json publicJwk() override;

 private:
  explicit SoftwareDeviceKey(std::shared_ptr<evp_pkey_st> k) : key_(std::move(k)) {}
  std::shared_ptr<evp_pkey_st> key_;
};

}  // namespace atlas
