// Shared by atlas-sso-broker and atlas-sso-native-host: the per-user SSO client wired to CNG keys, DPAPI (current user) and WinHTTP.
#pragma once
#include "atlas/devicesso.hpp"
#include "dpapi_store.hpp"
#include "winhttp_client.hpp"
#include "winkey.hpp"

#include <memory>

namespace win {

struct SsoSettings {
  std::string instanceUrl, publishableKey, instanceId;
};
// %ProgramData%\Atlas-Public\sso.json (written by atlas-enroll --write-config).
std::optional<SsoSettings> loadSsoSettings(std::string& err);
std::wstring ssoKeyName(const SsoSettings& s, const char* role);  // role: sign | enc | user

struct SsoRig {
  SsoSettings settings;
  DpapiStore store{true};
  atlas::SystemClock clock;
  WinHttpClient http;
  std::unique_ptr<CngDeviceKey> signing, enc, user;
  std::unique_ptr<atlas::SsoClient> client;
};

// create=true makes the three keys (replacing any), false opens them. Null with `err` on failure.
std::unique_ptr<SsoRig> openSsoRig(bool create, std::string& err, bool* hardware = nullptr);
void deleteSsoKeys(SsoRig& r);

}  // namespace win
