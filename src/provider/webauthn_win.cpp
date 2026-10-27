#include "webauthn_win.hpp"

#include "winutil.hpp"

#include <webauthn.h>

namespace win {

namespace {
// Struct versions used below need API version 4 (Windows 10 2004 and later); older systems report "not available".
constexpr DWORD kMinApiVersion = 4;

struct Api {
  HMODULE mod = nullptr;
  DWORD version = 0;
  decltype(&WebAuthNGetApiVersionNumber) getVersion = nullptr;
  decltype(&WebAuthNAuthenticatorGetAssertion) getAssertion = nullptr;
  decltype(&WebAuthNAuthenticatorMakeCredential) makeCredential = nullptr;
  decltype(&WebAuthNFreeAssertion) freeAssertion = nullptr;
  decltype(&WebAuthNFreeCredentialAttestation) freeAttestation = nullptr;
  decltype(&WebAuthNGetCancellationId) getCancellationId = nullptr;
  decltype(&WebAuthNCancelCurrentOperation) cancelOp = nullptr;
  bool ok() const { return mod && version >= kMinApiVersion && getAssertion && makeCredential && freeAssertion && freeAttestation && getCancellationId && cancelOp; }
};

const Api& api() {
  static const Api a = [] {
    Api x;
    // System32 only: never a webauthn.dll from the application or current directory.
    x.mod = LoadLibraryExW(L"webauthn.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!x.mod) return x;
    auto get = [&](const char* n) { return GetProcAddress(x.mod, n); };
    x.getVersion = reinterpret_cast<decltype(x.getVersion)>(get("WebAuthNGetApiVersionNumber"));
    x.getAssertion = reinterpret_cast<decltype(x.getAssertion)>(get("WebAuthNAuthenticatorGetAssertion"));
    x.makeCredential = reinterpret_cast<decltype(x.makeCredential)>(get("WebAuthNAuthenticatorMakeCredential"));
    x.freeAssertion = reinterpret_cast<decltype(x.freeAssertion)>(get("WebAuthNFreeAssertion"));
    x.freeAttestation = reinterpret_cast<decltype(x.freeAttestation)>(get("WebAuthNFreeCredentialAttestation"));
    x.getCancellationId = reinterpret_cast<decltype(x.getCancellationId)>(get("WebAuthNGetCancellationId"));
    x.cancelOp = reinterpret_cast<decltype(x.cancelOp)>(get("WebAuthNCancelCurrentOperation"));
    if (x.getVersion) x.version = x.getVersion();
    return x;
  }();
  return a;
}

DWORD uvRequirement(const std::string& s) {
  if (s == "required") return WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
  if (s == "discouraged") return WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
  return WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED;
}

DWORD transportMask(const std::vector<std::string>& ts) {
  DWORD m = 0;
  for (const auto& t : ts) {
    if (t == "usb") m |= WEBAUTHN_CTAP_TRANSPORT_USB;
    else if (t == "nfc") m |= WEBAUTHN_CTAP_TRANSPORT_NFC;
    else if (t == "ble") m |= WEBAUTHN_CTAP_TRANSPORT_BLE;
    else return 0;  // anything else (internal, hybrid, unknown): do not restrict, let the platform find the key
  }
  return m;
}

std::vector<std::string> transportNames(DWORD used) {
  std::vector<std::string> out;
  if (used & WEBAUTHN_CTAP_TRANSPORT_USB) out.push_back("usb");
  if (used & WEBAUTHN_CTAP_TRANSPORT_NFC) out.push_back("nfc");
  if (used & WEBAUTHN_CTAP_TRANSPORT_BLE) out.push_back("ble");
  return out;
}

std::string hr(HRESULT h) {
  char b[32];
  snprintf(b, sizeof b, "webauthn_0x%08lx", static_cast<unsigned long>(h));
  return b;
}

WEBAUTHN_CLIENT_DATA clientDataOf(const std::string& cd) {
  WEBAUTHN_CLIENT_DATA c{};
  c.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
  c.cbClientDataJSON = static_cast<DWORD>(cd.size());
  c.pbClientDataJSON = reinterpret_cast<PBYTE>(const_cast<char*>(cd.data()));
  c.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;
  return c;
}
}  // namespace

bool WinWebAuthn::available() { return api().ok(); }

HWND WinWebAuthn::ownerWindow() const {
  HWND h = owner_ ? owner_() : nullptr;
  if (!h) h = GetForegroundWindow();
  return h ? h : GetDesktopWindow();
}

void WinWebAuthn::cancel() {
  if (!active_ || !api().ok()) return;
  GUID id;
  {
    std::lock_guard<std::mutex> l(mu_);
    id = cancelId_;
  }
  api().cancelOp(&id);
}

std::optional<atlas::RawAssertion> WinWebAuthn::getAssertion(const atlas::PasskeyRequest& req, const std::string& clientData, std::string& err) {
  const Api& a = api();
  if (!a.ok()) { err = "webauthn_unavailable"; return std::nullopt; }
  {
    std::lock_guard<std::mutex> l(mu_);
    if (FAILED(a.getCancellationId(&cancelId_))) { err = "webauthn_cancel_id"; return std::nullopt; }
  }

  // At the sign-in screen only a roaming (cross-platform) authenticator can answer: Windows Hello's platform credentials
  // belong to a user profile that is not loaded yet.
  std::vector<WEBAUTHN_CREDENTIAL_EX> ex(req.allow.size());
  std::vector<PWEBAUTHN_CREDENTIAL_EX> ptrs(req.allow.size());
  for (size_t i = 0; i < req.allow.size(); i++) {
    ex[i] = {};
    ex[i].dwVersion = WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION;
    ex[i].cbId = static_cast<DWORD>(req.allow[i].id.size());
    ex[i].pbId = const_cast<PBYTE>(req.allow[i].id.data());
    ex[i].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    ex[i].dwTransports = transportMask(req.allow[i].transports);
    ptrs[i] = &ex[i];
  }
  WEBAUTHN_CREDENTIAL_LIST list{};
  list.cCredentials = static_cast<DWORD>(ptrs.size());
  list.ppCredentials = ptrs.data();

  WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS o{};
  o.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4;
  o.dwTimeoutMilliseconds = req.timeoutMs;
  o.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
  o.dwUserVerificationRequirement = uvRequirement(req.userVerification);
  o.pCancellationId = &cancelId_;
  if (!ptrs.empty()) o.pAllowCredentialList = &list;

  WEBAUTHN_CLIENT_DATA cd = clientDataOf(clientData);
  std::wstring rp = toWide(req.rpId);
  PWEBAUTHN_ASSERTION out = nullptr;
  active_ = true;
  HRESULT h = a.getAssertion(ownerWindow(), rp.c_str(), &cd, &o, &out);
  active_ = false;
  if (FAILED(h) || !out) { err = hr(h); return std::nullopt; }
  atlas::RawAssertion r;
  r.credentialId.assign(out->Credential.pbId, out->Credential.pbId + out->Credential.cbId);
  r.authenticatorData.assign(out->pbAuthenticatorData, out->pbAuthenticatorData + out->cbAuthenticatorData);
  r.signature.assign(out->pbSignature, out->pbSignature + out->cbSignature);
  a.freeAssertion(out);
  return r;
}

std::optional<atlas::RawAttestation> WinWebAuthn::makeCredential(const atlas::PasskeyCreation& req, const std::string& clientData, std::string& err) {
  const Api& a = api();
  if (!a.ok()) { err = "webauthn_unavailable"; return std::nullopt; }
  {
    std::lock_guard<std::mutex> l(mu_);
    if (FAILED(a.getCancellationId(&cancelId_))) { err = "webauthn_cancel_id"; return std::nullopt; }
  }
  std::wstring rpId = toWide(req.rpId), rpName = toWide(req.rpName), uName = toWide(req.userName), uDisplay = toWide(req.userDisplayName);
  WEBAUTHN_RP_ENTITY_INFORMATION rp{};
  rp.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
  rp.pwszId = rpId.c_str();
  rp.pwszName = rpName.c_str();
  WEBAUTHN_USER_ENTITY_INFORMATION user{};
  user.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
  user.cbId = static_cast<DWORD>(req.userId.size());
  user.pbId = const_cast<PBYTE>(req.userId.data());
  user.pwszName = uName.c_str();
  user.pwszDisplayName = uDisplay.c_str();

  std::vector<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> algs(req.algorithms.size());
  for (size_t i = 0; i < algs.size(); i++) {
    algs[i] = {};
    algs[i].dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    algs[i].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    algs[i].lAlg = req.algorithms[i];
  }
  WEBAUTHN_COSE_CREDENTIAL_PARAMETERS params{static_cast<DWORD>(algs.size()), algs.data()};

  std::vector<WEBAUTHN_CREDENTIAL_EX> ex(req.exclude.size());
  std::vector<PWEBAUTHN_CREDENTIAL_EX> ptrs(req.exclude.size());
  for (size_t i = 0; i < ex.size(); i++) {
    ex[i] = {};
    ex[i].dwVersion = WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION;
    ex[i].cbId = static_cast<DWORD>(req.exclude[i].size());
    ex[i].pbId = const_cast<PBYTE>(req.exclude[i].data());
    ex[i].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    ptrs[i] = &ex[i];
  }
  WEBAUTHN_CREDENTIAL_LIST excludeList{static_cast<DWORD>(ptrs.size()), ptrs.data()};

  WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS o{};
  o.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4;
  o.dwTimeoutMilliseconds = req.timeoutMs;
  o.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
  o.dwUserVerificationRequirement = uvRequirement(req.userVerification);
  o.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
  o.bPreferResidentKey = TRUE;
  o.pCancellationId = &cancelId_;
  if (!ptrs.empty()) o.pExcludeCredentialList = &excludeList;

  WEBAUTHN_CLIENT_DATA cd = clientDataOf(clientData);
  PWEBAUTHN_CREDENTIAL_ATTESTATION out = nullptr;
  active_ = true;
  HRESULT h = a.makeCredential(ownerWindow(), &rp, &user, &params, &cd, &o, &out);
  active_ = false;
  if (FAILED(h) || !out) { err = hr(h); return std::nullopt; }
  atlas::RawAttestation r;
  r.credentialId.assign(out->pbCredentialId, out->pbCredentialId + out->cbCredentialId);
  r.attestationObject.assign(out->pbAttestationObject, out->pbAttestationObject + out->cbAttestationObject);
  if (out->dwVersion >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3) r.transports = transportNames(out->dwUsedTransport);
  a.freeAttestation(out);
  return r;
}

}  // namespace win
