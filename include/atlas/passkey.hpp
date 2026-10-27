// WebAuthn pieces for the OS-login passkey factor: parsing the server's options, building the client data the platform API needs,
// shaping the assertion/attestation for the server, and the authenticator interface the Windows glue implements.
// Portable on purpose: everything here is unit-tested off Windows.
#pragma once
#include "atlas/client.hpp"
#include "atlas/gate.hpp"

namespace atlas {

struct PasskeyCredential {
  Bytes id;
  std::vector<std::string> transports;
};

struct PasskeyRequest {
  std::string challenge;  // base64url, as issued; also what goes into clientDataJSON
  std::string rpId;
  std::string origin;     // always "https://" + rpId; checked on parse
  std::string userVerification;  // required | preferred | discouraged
  std::vector<PasskeyCredential> allow;
  uint32_t timeoutMs = 60000;
};

struct PasskeyCreation {
  std::string challenge, rpId, rpName, origin, userVerification;
  Bytes userId;
  std::string userName, userDisplayName;
  std::vector<int> algorithms;  // COSE algorithm ids, in the server's order
  std::vector<Bytes> exclude;
  uint32_t timeoutMs = 60000;
};

struct RawAssertion {
  Bytes credentialId, authenticatorData, signature;
};
struct RawAttestation {
  Bytes credentialId, attestationObject;
  std::vector<std::string> transports;
};

// Both parsers fail closed: a missing field, an undecodable id, or an origin that is not exactly https://<rpId> is an error.
std::optional<PasskeyRequest> parsePasskeyRequest(const json& options, std::string& err);
std::optional<PasskeyCreation> parsePasskeyCreation(const json& options, std::string& err);

// {"type":"webauthn.get"|"webauthn.create","challenge":...,"origin":...,"crossOrigin":false}
std::string clientDataJson(const std::string& type, const std::string& challenge, const std::string& origin);

// Body of the `assertion` the server verifies.
json assertionJson(const std::string& clientData, const std::string& challenge, const RawAssertion& a);
// Body of the `credential` the server verifies at enrolment.
json credentialJson(const std::string& clientData, const std::string& challenge, const RawAttestation& a);

// The platform authenticator behind the credential provider (webauthn.dll on Windows). Out-of-band by nature: the call blocks
// while the platform shows its own prompt, so the host runs it on a worker thread and calls cancel() to abort.
struct IPasskeyAuthenticator {
  virtual ~IPasskeyAuthenticator() = default;
  virtual bool available() = 0;  // the platform API is present and recent enough
  virtual std::optional<RawAssertion> getAssertion(const PasskeyRequest& req, const std::string& clientData, std::string& err) = 0;
  virtual std::optional<RawAttestation> makeCredential(const PasskeyCreation& req, const std::string& clientData, std::string& err) = 0;
  virtual void cancel() = 0;
};

// LoginGate hook: runs the whole assertion for the options, or nullopt (cancelled, unsupported, malformed).
LoginGate::PasskeyFn makePasskeyFn(IPasskeyAuthenticator& auth);

struct PasskeyEnrolResult {
  bool ok = false;
  std::string error, passkeyId;
};
// Registers a passkey through this workstation. `proofChallengeId` is a challenge the user has just verified (push or code).
PasskeyEnrolResult enrollPasskey(Client& client, IPasskeyAuthenticator& auth, const std::string& proofChallengeId, const std::string& name);

}  // namespace atlas
