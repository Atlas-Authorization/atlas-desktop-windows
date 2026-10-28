#include "sso_common.hpp"

#include "winutil.hpp"

namespace win {

std::optional<SsoSettings> loadSsoSettings(std::string& err) {
  auto raw = readFile(ssoConfigPath());
  if (!raw) { err = "the Atlas SSO settings are not installed on this PC"; return std::nullopt; }
  atlas::json j = atlas::json::parse(std::string(raw->begin(), raw->end()), nullptr, false);
  if (j.is_discarded() || !j.is_object()) { err = "the Atlas SSO settings are damaged"; return std::nullopt; }
  SsoSettings s{j.value("instance_url", ""), j.value("publishable_key", ""), j.value("instance_id", "")};
  if (s.instanceUrl.rfind("https://", 0) != 0 || s.publishableKey.empty() || s.instanceId.empty()) {
    err = "the Atlas SSO settings are incomplete";
    return std::nullopt;
  }
  return s;
}

std::wstring ssoKeyName(const SsoSettings& s, const char* role) { return L"AtlasSso-" + toWide(s.instanceId) + L"-" + toWide(role); }

std::unique_ptr<SsoRig> openSsoRig(bool create, std::string& err, bool* hardware) {
  auto settings = loadSsoSettings(err);
  if (!settings) return nullptr;
  auto r = std::make_unique<SsoRig>();
  r->settings = *settings;
  if (create) {
    bool hw1 = false, hw2 = false, hw3 = false;
    r->signing = CngDeviceKey::create(ssoKeyName(*settings, "sign"), KeyKind::Signing, hw1, err, KeyScope::User, false);
    if (r->signing) r->enc = CngDeviceKey::create(ssoKeyName(*settings, "enc"), KeyKind::Seal, hw2, err, KeyScope::User, false);
    if (r->enc) r->user = CngDeviceKey::create(ssoKeyName(*settings, "user"), KeyKind::Signing, hw3, err, KeyScope::User, true);
    if (!r->user) { err = "could not create the device keys (" + err + ")"; deleteSsoKeys(*r); return nullptr; }
    if (hardware) *hardware = hw1 && hw2;
  } else {
    r->signing = CngDeviceKey::open(ssoKeyName(*settings, "sign"), KeyScope::User);
    r->enc = CngDeviceKey::open(ssoKeyName(*settings, "enc"), KeyScope::User);
    r->user = CngDeviceKey::open(ssoKeyName(*settings, "user"), KeyScope::User);
    if (!r->signing || !r->enc || !r->user) { err = "this PC is not registered for device sign-in (run: atlas-sso-broker register)"; return nullptr; }
  }
  r->client = std::make_unique<atlas::SsoClient>(settings->instanceUrl, settings->publishableKey, *r->signing, *r->enc, *r->user, r->http, r->store, r->clock);
  return r;
}

void deleteSsoKeys(SsoRig& r) {
  if (r.signing) r.signing->deleteKey();
  if (r.enc) r.enc->deleteKey();
  if (r.user) r.user->deleteKey();
}

}  // namespace win
