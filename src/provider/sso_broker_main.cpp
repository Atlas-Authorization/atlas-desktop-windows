// atlas-sso-broker.exe: device-bound sign-in for the current Windows user (desktop/DEVICE_SSO.md).
//   register --code C [--username U]   create this user's device keys, register them with Atlas, register the user key
//   login                              prove presence (Windows asks) and get a device-bound session
//   refresh [--force]                  rotate the refresh token (no prompt)
//   maintain [--interactive]           what the scheduled task runs: refresh when due; with --interactive also login when needed
//   web-session [--redirect URL]       complete a browser sign-in; prints the URL to open (redirect_to) or the ticket
//   status                             what this PC holds (never prints a token)
//   logout                             delete the keys and local state (the dashboard revokes the registration on the server)
// Exit codes: 0 ok, 1 failed, 2 not set up, 3 sign-in needed, 4 revoked by the administrator, 64 usage.
#include "sso_common.hpp"
#include "winutil.hpp"

#include <cstdio>

namespace {
int report(const atlas::SsoResult& r, const char* okMsg) {
  if (r.ok) { std::printf("%s\n", okMsg); return 0; }
  std::fprintf(stderr, "atlas-sso-broker: %s\n", r.error.c_str());
  if (r.error == "revoked") return 4;
  if (r.error == "no_session" || r.error == "session_expired" || r.error == "user_key_unavailable") return 3;
  return 1;
}
const char* arg(int argc, wchar_t** argv, const wchar_t* name, std::string& out) {
  for (int i = 2; i + 1 < argc; i++)
    if (std::wstring(argv[i]) == name) { out = win::toUtf8(argv[i + 1]); return out.c_str(); }
  return nullptr;
}
bool flag(int argc, wchar_t** argv, const wchar_t* name) {
  for (int i = 2; i < argc; i++)
    if (std::wstring(argv[i]) == name) return true;
  return false;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  std::wstring cmd = argc > 1 ? argv[1] : L"";
  std::string err;

  if (cmd == L"register") {
    std::string code, username;
    arg(argc, argv, L"--code", code);
    if (code.empty() && !win::readConsoleLine("Registration code: ", false, code)) { std::fprintf(stderr, "a registration code is required\n"); return 64; }
    if (!arg(argc, argv, L"--username", username)) username = win::toUtf8(win::currentUserName());
    bool hardware = false;
    auto rig = win::openSsoRig(true, err, &hardware);
    if (!rig) { std::fprintf(stderr, "atlas-sso-broker: %s\n", err.c_str()); return 2; }
    auto fail = [&](const atlas::SsoResult& r) {
      win::deleteSsoKeys(*rig);
      rig->client->forget();
      return report(r, "");
    };
    atlas::SsoResult r = rig->client->fetchConfiguration();
    if (!r.ok) return fail(r);
    wchar_t host[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD hl = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(host, &hl);
    r = rig->client->registerDevice(code, win::toUtf8(host), "windows", "0.2.0");
    if (!r.ok) return fail(r);
    r = rig->client->registerUser(username, "user_tpm_key");
    if (!r.ok) return fail(r);
    std::printf("Registered. Device keys: %s.\n", hardware ? "TPM" : "software key store (no TPM available to this user)");
    return 0;
  }

  if (cmd == L"status") {
    auto s = win::loadSsoSettings(err);
    if (!s) { std::printf("not set up: %s\n", err.c_str()); return 2; }
    auto rig = win::openSsoRig(false, err);
    if (!rig) { std::printf("not registered: %s\n", err.c_str()); return 2; }
    atlas::SsoState st = rig->client->state();
    int64_t now = rig->clock.nowMs();
    std::printf("instance: %s\nregistration: %s\nuser: %s\nsession: %s\nrefresh token: %s\n", s->instanceUrl.c_str(),
                st.registrationId.empty() ? "none" : st.registrationId.c_str(), st.username.c_str(),
                st.sessionExpiresAt > now ? "live" : "none", st.refreshExpiresAt > now && !st.refreshToken.empty() ? "valid" : "none");
    return 0;
  }

  if (cmd == L"logout") {
    auto rig = win::openSsoRig(false, err);
    if (!rig) { std::fprintf(stderr, "atlas-sso-broker: %s\n", err.c_str()); return 2; }
    win::deleteSsoKeys(*rig);
    rig->client->forget();
    std::printf("Removed this user's device keys and local state.\n");
    return 0;
  }

  if (cmd == L"login" || cmd == L"refresh" || cmd == L"maintain" || cmd == L"web-session") {
    auto rig = win::openSsoRig(false, err);
    if (!rig) { std::fprintf(stderr, "atlas-sso-broker: %s\n", err.c_str()); return 2; }
    atlas::SsoResult r = rig->client->fetchConfiguration();
    if (!r.ok) return report(r, "");
    int64_t now = rig->clock.nowMs();
    atlas::SsoState st = rig->client->state();
    if (cmd == L"login") return report(rig->client->login(), "Signed in with this device.");
    if (cmd == L"refresh") return report(rig->client->refresh(), "Refreshed.");
    if (cmd == L"web-session") {
      std::string redirect;
      arg(argc, argv, L"--redirect", redirect);
      atlas::WebSession w;
      r = rig->client->webSession(redirect, w);
      if (!r.ok) return report(r, "");
      std::printf("%s\n", w.redirectTo.empty() ? w.ticket.c_str() : w.redirectTo.c_str());  // a ticket is a credential: only to the user's own console
      return 0;
    }
    // maintain: refresh once half of the session is gone; sign in again (with a prompt) only when asked to.
    bool live = st.sessionExpiresAt > now;
    bool halfGone = st.sessionExpiresAt - now < static_cast<int64_t>(rig->client->endpoints().sessionMinutes) * 30000;  // under half the session left
    if (live && !halfGone) { std::printf("Session is fresh.\n"); return 0; }
    if (!st.refreshToken.empty() && st.refreshExpiresAt > now) {
      r = rig->client->refresh();
      if (r.ok) { std::printf("Refreshed.\n"); return 0; }
    }
    if (flag(argc, argv, L"--interactive")) return report(rig->client->login(), "Signed in with this device.");
    std::fprintf(stderr, "atlas-sso-broker: sign-in needed\n");
    return 3;
  }

  std::fprintf(stderr, "usage: atlas-sso-broker register --code C | login | refresh | maintain [--interactive] | web-session | status | logout\n");
  return 64;
}
