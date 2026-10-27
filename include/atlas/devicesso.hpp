// Device-bound SSO client (desktop/DEVICE_SSO.md): registration, Apple Platform SSO style login and refresh, JWE response opening,
// id_token verification and the browser web-session ticket. Portable: keys, HTTP and storage are the platform interfaces.
#pragma once
#include "atlas/base.hpp"

namespace atlas {

// ---- building blocks (unit-tested against Apple's published vectors) ----

// base64(SHA-256(0x04 || X || Y)), standard alphabet: the `kid` Apple specifies for a public key. Empty if the JWK is not P-256.
std::string jwkKid(const json& publicJwk);
// NIST SP 800-56A concatenation KDF with SHA-256 as used by JWE ECDH-ES (RFC 7518 4.6.2). apu/apv are the DECODED header values.
Bytes concatKdf(const Bytes& z, const std::string& algorithmId, const Bytes& apu, const Bytes& apv, uint32_t keyBits);
// Apple's PartyVInfo: len||"Apple" || len||<device encryption public point> || len||<login nonce>.
Bytes applePartyVInfo(const Bytes& encryptionPublicPoint, const std::string& nonce);
// Compact JWS, ES256 with P1363 signature.
std::string jwsSignEs256(IDeviceKey& key, const json& header, const json& body);
// Opens a compact JWE (ECDH-ES, A256GCM, empty encrypted key). `expectedApv` must equal the header's apv. nullopt on anything off.
std::optional<json> jweOpenEcdhEs(ISealKey& encryptionKey, const std::string& compact, const Bytes& expectedApv);
// Test/server-side counterpart of jweOpenEcdhEs, kept in the library so the round trip is testable.
std::string jweSealEcdhEs(ISealKey& ephemeral, const json& recipientPublicJwk, const json& payload, const Bytes& apv);
// Verifies an RS256/ES256 compact JWS against a JWKS and returns its claims. Checks iss, aud, exp (60 s skew) and the nonce when given.
std::optional<json> verifyIdToken(const std::string& jws, const json& jwks, const std::string& issuer, const std::string& audience,
                                  const std::string& nonce, int64_t nowSeconds);

// ---- client ----

struct SsoEndpoints {
  bool enabled = false;
  std::string instanceId, issuer, clientId, audience, tokenEndpoint, nonceEndpoint, jwksUri;
  int sessionMinutes = 480, refreshDays = 30;
};

struct SsoState {
  std::string registrationId, username, refreshToken, userId;
  int64_t refreshExpiresAt = 0, sessionExpiresAt = 0, loggedInAt = 0;  // epoch ms
  json toJson() const;
  static SsoState fromJson(const json& j);
};

struct SsoResult {
  bool ok = false;
  std::string error;  // short code: unreachable, not_enabled, rejected:<code>, bad_response, not_registered, revoked, ...
  int status = 0;
};

namespace store {
constexpr const char* kSsoState = "sso_state";
}

class SsoClient {
 public:
  SsoClient(std::string instanceUrl, std::string publishableKey, IDeviceKey& signing, ISealKey& encryption, IDeviceKey& user,
            IHttpClient& http, ISecretStore& store, IClock& clock)
      : base_(std::move(instanceUrl)), pk_(std::move(publishableKey)), signing_(signing), enc_(encryption), user_(user),
        http_(http), store_(store), clock_(clock) {
    while (!base_.empty() && base_.back() == '/') base_.pop_back();
  }

  SsoResult fetchConfiguration();  // fills endpoints(); refuses endpoints outside the instance URL
  const SsoEndpoints& endpoints() const { return ep_; }
  SsoResult registerDevice(const std::string& registrationToken, const std::string& hostname, const std::string& platform,
                           const std::string& agentVersion);
  SsoResult registerUser(const std::string& username, const std::string& method /* user_tpm_key */);
  SsoResult login();    // user presence: signs the embedded assertion with the user key
  SsoResult refresh();  // device signing key only; rotates the refresh token
  SsoResult webSession(std::string& ticketUrl);  // needs a live session
  SsoState state() const;
  void forget();  // drops the local state (not the server registration)

 private:
  SsoResult nonce(std::string& out);
  SsoResult tokenCall(const json& loginJwtBody, const std::string& typ, const Bytes& apv, const std::string& loginNonce, bool isLogin);
  SsoResult postJson(const std::string& path, const json& body, json& out, int okStatus);
  std::string base_, pk_;
  IDeviceKey& signing_;
  ISealKey& enc_;
  IDeviceKey& user_;
  IHttpClient& http_;
  ISecretStore& store_;
  IClock& clock_;
  SsoEndpoints ep_;
};

}  // namespace atlas
