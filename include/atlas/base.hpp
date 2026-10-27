// Encoding helpers, crypto primitives and the small platform interfaces.
#pragma once
#include <nlohmann/json.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace atlas {

using Bytes = std::vector<uint8_t>;
using json = nlohmann::json;

Bytes toBytes(const std::string& s);
std::string toString(const Bytes& b);

std::string b64uEncode(const Bytes& b);
std::string b64uEncode(const std::string& s);
// Unpadded base64url only; padding, whitespace and foreign characters are rejected.
std::optional<Bytes> b64uDecode(const std::string& s);
std::optional<Bytes> base32Decode(const std::string& s);
bool ctEqual(const Bytes& a, const Bytes& b);
bool ctEqual(const std::string& a, const std::string& b);

// ---- crypto (OpenSSL 3 EVP) ----
Bytes sha256(const Bytes& data);
Bytes hmac(const char* digest /* "SHA256" | "SHA1" */, const Bytes& key, const Bytes& data);
Bytes hkdfSha256(const Bytes& ikm, const Bytes& salt, const Bytes& info, size_t len);
bool aes256GcmDecrypt(const Bytes& key, const Bytes& iv, const Bytes& ct, const Bytes& tag, Bytes& out);
std::optional<Bytes> scryptDerive(const std::string& pass, const Bytes& salt, uint64_t N, uint64_t r, uint64_t p, size_t len);
Bytes randomBytes(size_t n);
// jwk: { kty:"EC", crv:"P-256", x, y }. Signature is IEEE P1363 (r||s, 64 bytes).
bool ecdsaVerifyP1363(const json& publicJwk, const Bytes& message, const Bytes& signature);

// ---- platform interfaces ----
struct IDeviceKey {
  virtual ~IDeviceKey() = default;
  // ECDSA P-256 over SHA-256 of `message`; returns 64 bytes r||s. Empty on failure.
  virtual Bytes sign(const Bytes& message) = 0;
  // ECDH with an uncompressed peer point (0x04||X||Y); returns the 32-byte X coordinate (big endian). Empty on failure.
  virtual Bytes ecdh(const Bytes& peerUncompressedPoint) = 0;
  virtual json publicJwk() = 0;
};

struct HttpResponse {
  int status = 0;  // 0 = transport failure (unreachable, TLS error, timeout)
  std::string body;
};

struct IHttpClient {
  virtual ~IHttpClient() = default;
  virtual HttpResponse post(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers,
                            const std::string& body) = 0;
};

struct ISecretStore {
  virtual ~ISecretStore() = default;
  virtual std::optional<Bytes> get(const std::string& name) = 0;
  virtual bool put(const std::string& name, const Bytes& value) = 0;
  virtual void remove(const std::string& name) = 0;
};

struct IClock {
  virtual ~IClock() = default;
  virtual int64_t nowMs() = 0;  // wall clock, epoch milliseconds
};

class MemorySecretStore : public ISecretStore {
 public:
  std::optional<Bytes> get(const std::string& name) override;
  bool put(const std::string& name, const Bytes& value) override;
  void remove(const std::string& name) override;
  std::map<std::string, Bytes> items;
};

class SystemClock : public IClock {
 public:
  int64_t nowMs() override;
};

// Convenience: store/load JSON documents and strings through an ISecretStore.
std::optional<json> getJson(ISecretStore& s, const std::string& name);
bool putJson(ISecretStore& s, const std::string& name, const json& j);
std::optional<std::string> getString(ISecretStore& s, const std::string& name);
bool putString(ISecretStore& s, const std::string& name, const std::string& v);

}  // namespace atlas
