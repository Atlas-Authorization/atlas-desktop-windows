#include "atlas/passkey.hpp"

#include <algorithm>

namespace atlas {

namespace {
bool wellFormedId(const std::string& s, size_t minBytes, Bytes* out = nullptr) {
  auto b = b64uDecode(s);
  if (!b || b->size() < minBytes || b->size() > 1024) return false;
  if (out) *out = *b;
  return true;
}
uint32_t clampTimeout(const json& o) {
  if (!o.contains("timeout") || !o["timeout"].is_number_integer()) return 60000;
  int64_t t = o["timeout"];
  return static_cast<uint32_t>(std::min<int64_t>(std::max<int64_t>(t, 10000), 120000));
}
bool uvValue(const std::string& s) { return s == "required" || s == "preferred" || s == "discouraged"; }
bool originMatches(const std::string& origin, const std::string& rpId) { return !rpId.empty() && origin == "https://" + rpId; }
}  // namespace

std::optional<PasskeyRequest> parsePasskeyRequest(const json& o, std::string& err) {
  if (!o.is_object()) { err = "options are not an object"; return std::nullopt; }
  PasskeyRequest r;
  r.challenge = o.value("challenge", "");
  r.rpId = o.value("rpId", "");
  r.origin = o.value("origin", "");
  r.userVerification = o.value("userVerification", "preferred");
  if (!wellFormedId(r.challenge, 16)) { err = "bad challenge"; return std::nullopt; }
  if (!originMatches(r.origin, r.rpId)) { err = "origin does not match the relying party"; return std::nullopt; }
  if (!uvValue(r.userVerification)) { err = "bad userVerification"; return std::nullopt; }
  if (o.contains("allowCredentials")) {
    if (!o["allowCredentials"].is_array()) { err = "bad allowCredentials"; return std::nullopt; }
    for (const auto& c : o["allowCredentials"]) {
      PasskeyCredential pc;
      if (!c.is_object() || !c.contains("id") || !c["id"].is_string() || !wellFormedId(c["id"], 1, &pc.id)) { err = "bad credential id"; return std::nullopt; }
      if (c.contains("transports") && c["transports"].is_array())
        for (const auto& t : c["transports"])
          if (t.is_string()) pc.transports.push_back(t);
      r.allow.push_back(std::move(pc));
    }
  }
  r.timeoutMs = clampTimeout(o);
  return r;
}

std::optional<PasskeyCreation> parsePasskeyCreation(const json& o, std::string& err) {
  if (!o.is_object()) { err = "options are not an object"; return std::nullopt; }
  PasskeyCreation c;
  c.challenge = o.value("challenge", "");
  c.origin = o.value("origin", "");
  c.userVerification = "preferred";
  if (!wellFormedId(c.challenge, 16)) { err = "bad challenge"; return std::nullopt; }
  if (!o.contains("rp") || !o["rp"].is_object()) { err = "missing rp"; return std::nullopt; }
  c.rpId = o["rp"].value("id", "");
  c.rpName = o["rp"].value("name", "Atlas");
  if (!originMatches(c.origin, c.rpId)) { err = "origin does not match the relying party"; return std::nullopt; }
  if (!o.contains("user") || !o["user"].is_object() || !wellFormedId(o["user"].value("id", ""), 1, &c.userId)) { err = "bad user"; return std::nullopt; }
  c.userName = o["user"].value("name", "");
  c.userDisplayName = o["user"].value("displayName", c.userName);
  if (c.userName.empty()) { err = "bad user"; return std::nullopt; }
  if (o.contains("authenticatorSelection") && o["authenticatorSelection"].is_object()) {
    c.userVerification = o["authenticatorSelection"].value("userVerification", "preferred");
    if (!uvValue(c.userVerification)) { err = "bad userVerification"; return std::nullopt; }
  }
  if (o.contains("pubKeyCredParams") && o["pubKeyCredParams"].is_array())
    for (const auto& p : o["pubKeyCredParams"])
      if (p.is_object() && p.value("type", "") == "public-key" && p.contains("alg") && p["alg"].is_number_integer()) c.algorithms.push_back(p["alg"]);
  if (c.algorithms.empty()) { err = "no usable algorithm"; return std::nullopt; }
  if (o.contains("excludeCredentials") && o["excludeCredentials"].is_array())
    for (const auto& e : o["excludeCredentials"]) {
      Bytes id;
      if (e.is_object() && e.contains("id") && e["id"].is_string() && wellFormedId(e["id"], 1, &id)) c.exclude.push_back(std::move(id));
    }
  c.timeoutMs = clampTimeout(o);
  return c;
}

std::string clientDataJson(const std::string& type, const std::string& challenge, const std::string& origin) {
  return json{{"type", type}, {"challenge", challenge}, {"origin", origin}, {"crossOrigin", false}}.dump();
}

json assertionJson(const std::string& clientData, const std::string& challenge, const RawAssertion& a) {
  return {{"challenge", challenge}, {"credential_id", b64uEncode(a.credentialId)}, {"authenticator_data", b64uEncode(a.authenticatorData)},
          {"client_data_json", b64uEncode(clientData)}, {"signature", b64uEncode(a.signature)}};
}

json credentialJson(const std::string& clientData, const std::string& challenge, const RawAttestation& a) {
  return {{"challenge", challenge}, {"attestation_object", b64uEncode(a.attestationObject)}, {"client_data_json", b64uEncode(clientData)}};
}

LoginGate::PasskeyFn makePasskeyFn(IPasskeyAuthenticator& auth) {
  return [&auth](const json& options) -> std::optional<json> {
    std::string err;
    auto req = parsePasskeyRequest(options, err);
    if (!req || !auth.available()) return std::nullopt;
    std::string cd = clientDataJson("webauthn.get", req->challenge, req->origin);
    auto a = auth.getAssertion(*req, cd, err);
    if (!a || a->credentialId.empty() || a->authenticatorData.empty() || a->signature.empty()) return std::nullopt;
    return assertionJson(cd, req->challenge, *a);
  };
}

PasskeyEnrolResult enrollPasskey(Client& client, IPasskeyAuthenticator& auth, const std::string& proofChallengeId, const std::string& name) {
  PasskeyEnrolResult out;
  if (!auth.available()) { out.error = "no WebAuthn platform support"; return out; }
  ApiResult o = client.passkeyOptions(proofChallengeId);
  if (o.unreachable()) { out.error = "server unreachable"; return out; }
  if (!o.ok() || !o.body.is_object() || !o.body.contains("passkey_options") || !o.body["registration_id"].is_string()) {
    out.error = o.errorCode().empty() ? "registration refused (" + std::to_string(o.status) + ")" : o.errorCode();
    return out;
  }
  std::string err;
  auto req = parsePasskeyCreation(o.body["passkey_options"], err);
  if (!req) { out.error = err; return out; }
  std::string cd = clientDataJson("webauthn.create", req->challenge, req->origin);
  auto att = auth.makeCredential(*req, cd, err);
  if (!att || att->attestationObject.empty() || att->credentialId.empty()) { out.error = err.empty() ? "cancelled" : err; return out; }
  ApiResult f = client.passkeyEnrol(o.body["registration_id"], credentialJson(cd, req->challenge, *att), name, att->transports);
  if (f.unreachable()) { out.error = "server unreachable"; return out; }
  if (!f.ok() || !f.body.is_object()) { out.error = f.errorCode().empty() ? "registration refused (" + std::to_string(f.status) + ")" : f.errorCode(); return out; }
  out.passkeyId = f.body.value("id", "");
  out.ok = true;
  return out;
}

}  // namespace atlas
