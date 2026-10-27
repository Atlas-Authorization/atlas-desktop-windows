#include "atlas/devicesso.hpp"

#include "crypto_internal.hpp"

#include <cctype>

namespace atlas {

namespace {
void be32(Bytes& o, uint32_t v) {
  for (int s = 24; s >= 0; s -= 8) o.push_back(static_cast<uint8_t>(v >> s));
}
void lv(Bytes& o, const Bytes& d) {
  be32(o, static_cast<uint32_t>(d.size()));
  o.insert(o.end(), d.begin(), d.end());
}
std::vector<std::string> split(const std::string& s, char sep) {
  std::vector<std::string> out;
  size_t at = 0;
  for (;;) {
    size_t i = s.find(sep, at);
    out.push_back(s.substr(at, i == std::string::npos ? std::string::npos : i - at));
    if (i == std::string::npos) return out;
    at = i + 1;
  }
}
std::optional<json> parseSegment(const std::string& seg) {
  auto raw = b64uDecode(seg);
  if (!raw) return std::nullopt;
  json j = json::parse(toString(*raw), nullptr, false);
  if (j.is_discarded() || !j.is_object()) return std::nullopt;
  return j;
}
std::string urlEncode(const std::string& s) {
  static const char* hex = "0123456789ABCDEF";
  std::string o;
  for (unsigned char c : s) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') o += static_cast<char>(c);
    else { o += '%'; o += hex[c >> 4]; o += hex[c & 15]; }
  }
  return o;
}
std::string host(const std::string& url) {
  if (url.rfind("https://", 0) != 0) return {};
  size_t e = url.find_first_of("/?#", 8);
  std::string h = url.substr(8, e == std::string::npos ? std::string::npos : e - 8);
  return h.find('@') == std::string::npos ? h : std::string();
}
std::string errorCodeOf(const json& body) {
  if (!body.is_object()) return "unknown";
  if (body.contains("errors") && body["errors"].is_array() && !body["errors"].empty() && body["errors"][0].is_object())
    return body["errors"][0].value("code", "unknown");
  if (body.contains("error") && body["error"].is_string()) return body["error"];
  return "unknown";
}
json parseBody(const HttpResponse& r) {
  json j = json::parse(r.body, nullptr, false);
  return j.is_discarded() ? json() : j;
}
SsoResult fail(const HttpResponse& r, const json& body) {
  SsoResult o;
  o.status = r.status;
  o.error = r.status == 0 || r.status >= 500 ? "unreachable" : r.status == 403 ? "revoked" : "rejected:" + errorCodeOf(body);
  return o;
}
SsoResult bad(const char* why) { SsoResult o; o.error = why; return o; }
std::string randomHex(size_t n) {
  static const char* hex = "0123456789abcdef";
  std::string o;
  for (uint8_t b : randomBytes(n)) { o += hex[b >> 4]; o += hex[b & 15]; }
  return o;
}
const char* kScope = "openid offline_access urn:apple:platformsso";
const char* kJwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
}  // namespace

std::string jwkKid(const json& jwk) {
  auto pt = detail::pointFromJwk(jwk);
  return pt ? b64Encode(sha256(*pt)) : std::string();
}

Bytes concatKdf(const Bytes& z, const std::string& algorithmId, const Bytes& apu, const Bytes& apv, uint32_t keyBits) {
  Bytes in;
  be32(in, 1);  // one round: SHA-256 gives 256 bits
  in.insert(in.end(), z.begin(), z.end());
  lv(in, toBytes(algorithmId));
  lv(in, apu);
  lv(in, apv);
  be32(in, keyBits);
  return sha256(in);
}

Bytes applePartyVInfo(const Bytes& point, const std::string& nonce) {
  Bytes o;
  lv(o, toBytes("Apple"));
  lv(o, point);
  lv(o, toBytes(nonce));
  return o;
}

std::string jwsSignEs256(IDeviceKey& key, const json& header, const json& body) {
  std::string input = b64uEncode(header.dump()) + "." + b64uEncode(body.dump());
  Bytes sig = key.sign(toBytes(input));
  return sig.size() == 64 ? input + "." + b64uEncode(sig) : std::string();
}

std::optional<json> jweOpenEcdhEs(ISealKey& key, const std::string& compact, const Bytes& expectedApv) {
  auto p = split(compact, '.');
  if (p.size() != 5 || !p[1].empty()) return std::nullopt;  // direct key agreement: no encrypted key
  auto h = parseSegment(p[0]);
  if (!h || h->value("alg", "") != "ECDH-ES" || h->value("enc", "") != "A256GCM") return std::nullopt;
  if (!h->contains("epk")) return std::nullopt;
  auto point = detail::pointFromJwk((*h)["epk"]);
  auto apu = b64uDecode(h->value("apu", ""));
  auto iv = b64uDecode(p[2]), ct = b64uDecode(p[3]), tag = b64uDecode(p[4]);
  if (!point || !apu || apu->empty() || !iv || iv->size() != 12 || !ct || !tag || tag->size() != 16) return std::nullopt;
  if (h->contains("apv")) {
    auto got = b64uDecode((*h)["apv"].is_string() ? (*h)["apv"].get<std::string>() : "");
    if (!got || !ctEqual(*got, expectedApv)) return std::nullopt;  // the response must answer THIS request
  }
  Bytes z = key.ecdh(*point);
  if (z.size() != 32) return std::nullopt;
  Bytes k = concatKdf(z, "A256GCM", *apu, expectedApv, 256), plain;
  if (!aes256GcmDecrypt(k, *iv, *ct, *tag, plain, toBytes(p[0]))) return std::nullopt;
  json out = json::parse(toString(plain), nullptr, false);
  if (out.is_discarded() || !out.is_object()) return std::nullopt;
  return out;
}

std::string jweSealEcdhEs(ISealKey& eph, const json& recipient, const json& payload, const Bytes& apv) {
  auto rp = detail::pointFromJwk(recipient);
  auto ep = detail::pointFromJwk(eph.publicJwk());
  if (!rp || !ep) return {};
  Bytes apu;
  lv(apu, toBytes("APPLE"));
  lv(apu, *ep);
  Bytes z = eph.ecdh(*rp);
  if (z.size() != 32) return {};
  json header = {{"alg", "ECDH-ES"}, {"enc", "A256GCM"}, {"typ", "platformsso-login-response+jwt"}, {"epk", eph.publicJwk()},
                 {"apu", b64uEncode(apu)}, {"apv", b64uEncode(apv)}};
  std::string h = b64uEncode(header.dump());
  Bytes iv = randomBytes(12), ct, tag;
  if (!aes256GcmEncrypt(concatKdf(z, "A256GCM", apu, apv, 256), iv, toBytes(payload.dump()), ct, tag, toBytes(h))) return {};
  return h + ".." + b64uEncode(iv) + "." + b64uEncode(ct) + "." + b64uEncode(tag);
}

std::optional<json> verifyIdToken(const std::string& jws, const json& jwks, const std::string& issuer, const std::string& audience,
                                  const std::string& nonce, int64_t now) {
  auto p = split(jws, '.');
  if (p.size() != 3) return std::nullopt;
  auto h = parseSegment(p[0]);
  auto claims = parseSegment(p[1]);
  auto sig = b64uDecode(p[2]);
  if (!h || !claims || !sig || !jwks.is_object() || !jwks.contains("keys") || !jwks["keys"].is_array()) return std::nullopt;
  std::string alg = h->value("alg", ""), kid = h->value("kid", "");
  if (alg != "RS256" && alg != "ES256") return std::nullopt;  // the instance signs with exactly these
  Bytes input = toBytes(p[0] + "." + p[1]);
  bool ok = false;
  for (const auto& k : jwks["keys"]) {
    if (!k.is_object() || k.value("kid", "") != kid) continue;
    if (alg == "RS256" && k.value("kty", "") == "RSA") {
      auto n = b64uDecode(k.value("n", "")), e = b64uDecode(k.value("e", ""));
      ok = n && e && rsaVerifyPkcs1Sha256(*n, *e, input, *sig);
    } else if (alg == "ES256" && k.value("kty", "") == "EC") {
      ok = ecdsaVerifyP1363(k, input, *sig);
    }
    break;
  }
  if (!ok) return std::nullopt;
  if (claims->value("iss", "") != issuer) return std::nullopt;
  const json& aud = (*claims)["aud"];
  bool audOk = aud.is_string() ? aud == audience : false;
  if (aud.is_array())
    for (const auto& a : aud) audOk = audOk || (a.is_string() && a == audience);
  if (!audOk) return std::nullopt;
  if (!claims->contains("exp") || !(*claims)["exp"].is_number() || (*claims)["exp"].get<int64_t>() + 60 < now) return std::nullopt;
  if (!nonce.empty() && claims->value("nonce", "") != nonce) return std::nullopt;
  return *claims;
}

// ---- state ----

json SsoState::toJson() const {
  return {{"registration_id", registrationId}, {"username", username}, {"refresh_token", refreshToken}, {"user_id", userId},
          {"refresh_expires_at", refreshExpiresAt}, {"session_expires_at", sessionExpiresAt}, {"logged_in_at", loggedInAt}};
}
SsoState SsoState::fromJson(const json& j) {
  SsoState s;
  if (!j.is_object()) return s;
  s.registrationId = j.value("registration_id", "");
  s.username = j.value("username", "");
  s.refreshToken = j.value("refresh_token", "");
  s.userId = j.value("user_id", "");
  s.refreshExpiresAt = j.value("refresh_expires_at", static_cast<int64_t>(0));
  s.sessionExpiresAt = j.value("session_expires_at", static_cast<int64_t>(0));
  s.loggedInAt = j.value("logged_in_at", static_cast<int64_t>(0));
  return s;
}
SsoState SsoClient::state() const {
  auto j = getJson(store_, store::kSsoState);
  return j ? SsoState::fromJson(*j) : SsoState{};
}
void SsoClient::forget() { store_.remove(store::kSsoState); }

// ---- client ----

SsoResult SsoClient::fetchConfiguration() {
  HttpResponse r = http_.get(base_ + "/v1/client/device_sso/configuration", {{"X-Publishable-Key", pk_}});
  json b = parseBody(r);
  if (r.status != 200 || !b.is_object()) return fail(r, b);
  SsoEndpoints e;
  e.enabled = b.value("enabled", false);
  e.instanceId = b.value("instance_id", "");
  e.issuer = b.value("issuer", "");
  e.clientId = b.value("client_id", "");
  e.audience = b.value("audience", "");
  e.tokenEndpoint = b.value("token_endpoint", "");
  e.nonceEndpoint = b.value("nonce_endpoint", "");
  e.jwksUri = b.value("jwks_uri", "");
  e.sessionMinutes = b.value("session_minutes", 480);
  e.refreshDays = b.value("refresh_days", 30);
  // Every signed request goes to these URLs, so they must stay on the instance we were configured with.
  std::string bh = host(base_);
  if (!e.enabled) return bad("not_enabled");
  if (e.instanceId.empty() || e.clientId != pk_ || e.audience.empty() || host(e.tokenEndpoint) != bh || host(e.nonceEndpoint) != bh ||
      host(e.jwksUri).empty() || e.issuer.rfind("https://", 0) != 0)
    return bad("bad_configuration");
  ep_ = e;
  return {true, "", 200};
}

SsoResult SsoClient::postJson(const std::string& path, const json& body, json& out, int okStatus) {
  HttpResponse r = http_.post(base_ + "/v1/client/device_sso/" + path, {{"X-Publishable-Key", pk_}, {"Content-Type", "application/json"}}, body.dump());
  out = parseBody(r);
  if (r.status != okStatus || !out.is_object()) return fail(r, out);
  return {true, "", r.status};
}

SsoResult SsoClient::nonce(std::string& out) {
  if (ep_.nonceEndpoint.empty()) return bad("no_configuration");
  HttpResponse r = http_.post(ep_.nonceEndpoint, {{"X-Publishable-Key", pk_}, {"Content-Type", "application/x-www-form-urlencoded"}},
                              "grant_type=srv_challenge&publishable_key=" + urlEncode(pk_));
  json b = parseBody(r);
  if (r.status != 200 || !b.is_object() || !b.contains("Nonce") || !b["Nonce"].is_string() || b["Nonce"].get<std::string>().empty())
    return r.status == 200 ? bad("bad_response") : fail(r, b);
  out = b["Nonce"];
  return {true, "", 200};
}

SsoResult SsoClient::registerDevice(const std::string& token, const std::string& hostname, const std::string& platform, const std::string& version) {
  if (ep_.instanceId.empty()) return bad("no_configuration");
  json spub = signing_.publicJwk();
  std::string kid = jwkKid(spub);
  Bytes sig = signing_.sign(toBytes(signedMessage("sso_device", ep_.instanceId, kid, token)));
  if (kid.empty() || sig.size() != 64) return bad("key_error");
  json out;
  SsoResult r = postJson("register_device",
                         {{"registration_token", token}, {"signing_public_key", spub}, {"encryption_public_key", enc_.publicJwk()},
                          {"signature", b64uEncode(sig)}, {"hostname", hostname}, {"platform", platform}, {"agent_version", version}},
                         out, 201);
  if (!r.ok) return r;
  if (!out.contains("id") || !out["id"].is_string()) return bad("bad_response");
  SsoState s;
  s.registrationId = out["id"];
  s.userId = out.value("user_id", "");
  putJson(store_, store::kSsoState, s.toJson());
  return r;
}

SsoResult SsoClient::registerUser(const std::string& username, const std::string& method) {
  SsoState s = state();
  if (s.registrationId.empty()) return bad("not_registered");
  std::string n;
  SsoResult nr = nonce(n);
  if (!nr.ok) return nr;
  json upub = user_.publicJwk();
  std::string ukid = jwkKid(upub);
  Bytes sig = signing_.sign(toBytes(signedMessage("sso_user", ep_.instanceId, s.registrationId, n, ukid)));
  if (ukid.empty() || sig.size() != 64) return bad("key_error");
  json out;
  SsoResult r = postJson("register_user",
                         {{"registration_id", s.registrationId}, {"nonce", n}, {"user_public_key", upub}, {"local_username", username},
                          {"method", method}, {"signature", b64uEncode(sig)}},
                         out, 200);
  if (!r.ok) return r;
  s.username = username;
  putJson(store_, store::kSsoState, s.toJson());
  return r;
}

SsoResult SsoClient::tokenCall(const json& body, const std::string& typ, const Bytes& apv, const std::string& loginNonce, bool) {
  json header = {{"typ", typ}, {"alg", "ES256"}, {"kid", jwkKid(signing_.publicJwk())}};
  std::string jwt = jwsSignEs256(signing_, header, body);
  if (jwt.empty()) return bad("key_error");
  HttpResponse r = http_.post(ep_.tokenEndpoint,
                              {{"X-Publishable-Key", pk_}, {"Content-Type", "application/x-www-form-urlencoded"},
                               {"Accept", "application/platformsso-login-response+jwt"}},
                              std::string("platform_sso_version=1.0&grant_type=") + urlEncode(kJwtBearer) + "&assertion=" + urlEncode(jwt) +
                                  "&publishable_key=" + urlEncode(pk_));
  if (r.status != 200) return fail(r, parseBody(r));
  auto plain = jweOpenEcdhEs(enc_, r.body, apv);
  if (!plain || !plain->contains("id_token") || !(*plain)["id_token"].is_string() || !plain->contains("refresh_token") ||
      !(*plain)["refresh_token"].is_string())
    return bad("bad_response");
  // The id_token proves the server that answered holds the instance signing key.
  HttpResponse jr = http_.get(ep_.jwksUri, {});
  json jwks = parseBody(jr);
  int64_t now = clock_.nowMs() / 1000;
  auto claims = jr.status == 200 ? verifyIdToken((*plain)["id_token"], jwks, ep_.issuer, ep_.clientId, loginNonce, now) : std::nullopt;
  if (!claims) return jr.status == 200 ? bad("id_token_invalid") : bad("unreachable");
  SsoState s = state();
  s.refreshToken = (*plain)["refresh_token"];
  s.userId = claims->value("sub", s.userId);
  int64_t expiresIn = plain->value("expires_in", static_cast<int64_t>(ep_.sessionMinutes) * 60);
  int64_t refreshIn = plain->value("refresh_token_expires_in", expiresIn);
  s.sessionExpiresAt = clock_.nowMs() + expiresIn * 1000;
  s.refreshExpiresAt = clock_.nowMs() + refreshIn * 1000;
  if (body.value("grant_type", "") != "refresh_token" || s.loggedInAt == 0) s.loggedInAt = clock_.nowMs();
  if (!putJson(store_, store::kSsoState, s.toJson())) return bad("store_error");
  return {true, "", 200};
}

SsoResult SsoClient::login() {
  SsoState s = state();
  if (s.registrationId.empty() || s.username.empty()) return bad("not_registered");
  std::string srv;
  SsoResult nr = nonce(srv);
  if (!nr.ok) return nr;
  json epub = enc_.publicJwk();
  auto point = detail::pointFromJwk(epub);
  if (!point) return bad("key_error");
  std::string ln = randomHex(16);
  Bytes apv = applePartyVInfo(*point, ln);
  int64_t now = clock_.nowMs() / 1000;
  std::string assertion = jwsSignEs256(user_, {{"typ", "JWT"}, {"alg", "ES256"}, {"kid", jwkKid(user_.publicJwk())}},
                                       {{"aud", ep_.audience}, {"iss", s.username}, {"sub", s.username}, {"iat", now}, {"exp", now + 300},
                                        {"nonce", ln}, {"request_nonce", srv}, {"scope", kScope}});
  if (assertion.empty()) return bad("user_key_unavailable");  // declined presence prompt or key gone
  json body = {{"client_id", pk_}, {"iss", pk_}, {"aud", ep_.tokenEndpoint}, {"iat", now}, {"exp", now + 300}, {"nonce", ln},
               {"request_nonce", srv}, {"scope", kScope}, {"username", s.username}, {"sub", s.username},
               {"grant_type", kJwtBearer}, {"assertion", assertion},
               {"jwe_crypto", {{"alg", "ECDH-ES"}, {"enc", "A256GCM"}, {"apv", b64uEncode(apv)}}}};
  return tokenCall(body, "platformsso-login-request+jwt", apv, ln, true);
}

SsoResult SsoClient::refresh() {
  SsoState s = state();
  if (s.registrationId.empty() || s.refreshToken.empty()) return bad("no_session");
  if (s.refreshExpiresAt <= clock_.nowMs()) return bad("session_expired");
  std::string srv;
  SsoResult nr = nonce(srv);
  if (!nr.ok) return nr;
  auto point = detail::pointFromJwk(enc_.publicJwk());
  if (!point) return bad("key_error");
  std::string ln = randomHex(16);
  Bytes apv = applePartyVInfo(*point, ln);
  int64_t now = clock_.nowMs() / 1000;
  json body = {{"client_id", pk_}, {"iss", pk_}, {"aud", ep_.tokenEndpoint}, {"iat", now}, {"exp", now + 300}, {"nonce", ln},
               {"request_nonce", srv}, {"scope", kScope}, {"grant_type", "refresh_token"}, {"refresh_token", s.refreshToken},
               {"jwe_crypto", {{"alg", "ECDH-ES"}, {"enc", "A256GCM"}, {"apv", b64uEncode(apv)}}}};
  SsoResult r = tokenCall(body, "platformsso-refresh-request+jwt", apv, ln, false);
  // A refused refresh means the family is gone (rotated elsewhere, revoked): keep nothing that looks usable.
  if (!r.ok && (r.error == "revoked" || r.error.rfind("rejected:", 0) == 0)) {
    s.refreshToken.clear();
    s.sessionExpiresAt = s.refreshExpiresAt = 0;
    putJson(store_, store::kSsoState, s.toJson());
  }
  return r;
}

SsoResult SsoClient::webSession(const std::string& redirectUrl, WebSession& out) {
  SsoState s = state();
  if (s.registrationId.empty()) return bad("not_registered");
  if (s.sessionExpiresAt <= clock_.nowMs()) return bad("no_session");
  if (!redirectUrl.empty() && host(redirectUrl).empty()) return bad("bad_redirect");
  std::string n;
  SsoResult nr = nonce(n);
  if (!nr.ok) return nr;
  std::string rh = redirectUrl.empty() ? "-" : b64uEncode(sha256(toBytes(redirectUrl)));
  Bytes sig = signing_.sign(toBytes(signedMessage("sso_web", ep_.instanceId, s.registrationId, n, rh)));
  if (sig.size() != 64) return bad("key_error");
  json body = {{"registration_id", s.registrationId}, {"nonce", n}, {"signature", b64uEncode(sig)}};
  if (!redirectUrl.empty()) body["redirect_url"] = redirectUrl;
  json res;
  SsoResult r = postJson("web_session", body, res, 201);
  if (!r.ok) return r;
  WebSession w;
  w.attemptId = res.value("attempt_id", "");
  w.status = res.value("status", "");
  w.ticket = res["ticket"].is_string() ? res["ticket"].get<std::string>() : "";
  w.redirectTo = res["redirect_to"].is_string() ? res["redirect_to"].get<std::string>() : "";
  w.expiresAt = res.value("expires_at", static_cast<int64_t>(0));
  if (w.attemptId.empty() || w.status.empty()) return bad("bad_response");
  // Never hand a browser a URL on a host we did not ask for.
  if (!w.redirectTo.empty() && (redirectUrl.empty() || host(w.redirectTo) != host(redirectUrl))) return bad("bad_response");
  out = w;
  return r;
}

}  // namespace atlas
