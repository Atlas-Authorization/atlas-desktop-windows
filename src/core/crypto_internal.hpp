#pragma once
#include "atlas/base.hpp"

#include <openssl/evp.h>

namespace atlas::detail {
using EvpPkey = std::shared_ptr<EVP_PKEY>;
EvpPkey pkeyFromPoint(const Bytes& uncompressedPoint, const Bytes* privateScalar);
std::optional<Bytes> pointFromJwk(const json& jwk);
Bytes derToP1363(const Bytes& der);
}  // namespace atlas::detail
