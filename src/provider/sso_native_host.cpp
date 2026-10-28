// atlas-sso-native-host.exe: browser native-messaging host (Chrome, Edge, Firefox). The reference extension asks it for a one-time
// sign-in URL for the Atlas instance; the host answers from the current user's device-bound session and never returns a token.
//   in : { "type": "get_ticket", "redirect_url": "https://app/..." }   (stdin: 4-byte little-endian length, then UTF-8 JSON; redirect_url optional)
//   out: { "ok": true, "redirect_to": "https://app/...?__atlas_attempt=..&__atlas_ticket=..", "ticket", "attempt_id", "status" }
//        | { "ok": false, "error": "login_required" | ... }
// The browser only lets the extensions named in the host manifest start this program.
#include "sso_common.hpp"

#include <fcntl.h>
#include <io.h>

#include <cstdint>
#include <cstdio>

namespace {
bool readMessage(std::string& out) {
  uint32_t n = 0;
  if (std::fread(&n, 1, 4, stdin) != 4 || n == 0 || n > 4096) return false;
  out.resize(n);
  return std::fread(out.data(), 1, n, stdin) == n;
}
void writeMessage(const atlas::json& j) {
  std::string s = j.dump();
  uint32_t n = static_cast<uint32_t>(s.size());
  std::fwrite(&n, 1, 4, stdout);
  std::fwrite(s.data(), 1, s.size(), stdout);
  std::fflush(stdout);
}
}  // namespace

int main() {
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
  std::string raw;
  if (!readMessage(raw)) return 1;
  atlas::json req = atlas::json::parse(raw, nullptr, false);
  if (req.is_discarded() || !req.is_object() || req.value("type", "") != "get_ticket") {
    writeMessage({{"ok", false}, {"error", "bad_request"}});
    return 1;
  }
  std::string err;
  auto rig = win::openSsoRig(false, err);
  if (!rig) { writeMessage({{"ok", false}, {"error", "not_registered"}}); return 0; }
  atlas::SsoResult r = rig->client->fetchConfiguration();
  atlas::SsoState st = rig->client->state();
  int64_t now = rig->clock.nowMs();
  // A stale session is refreshed quietly; a missing one needs the user to sign in with the broker (the host never prompts).
  if (r.ok && st.sessionExpiresAt <= now && !st.refreshToken.empty() && st.refreshExpiresAt > now) r = rig->client->refresh();
  atlas::WebSession w;
  if (r.ok) r = rig->client->webSession(req.value("redirect_url", ""), w);
  if (r.ok) writeMessage({{"ok", true}, {"redirect_to", w.redirectTo}, {"ticket", w.ticket}, {"attempt_id", w.attemptId}, {"status", w.status}});
  else writeMessage({{"ok", false}, {"error", r.error == "no_session" || r.error == "session_expired" ? "login_required" : r.error}});
  return 0;
}
