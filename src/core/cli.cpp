#include "atlas/cli.hpp"

#include <algorithm>
#include <cctype>

namespace atlas {

namespace {
bool digits(const std::string& s, size_t lo, size_t hi) {
  return s.size() >= lo && s.size() <= hi && std::all_of(s.begin(), s.end(), [](unsigned char c) { return c >= '0' && c <= '9'; });
}
bool validService(const std::string& s) {
  return !s.empty() && s.size() <= 31 && s[0] != '-' && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isalnum(c) || c == '.' || c == '_' || c == '-'; });
}
std::vector<std::string> words(const std::string& s) {
  std::vector<std::string> o;
  size_t at = 0;
  for (;;) {
    size_t i = s.find(' ', at);
    o.push_back(s.substr(at, i == std::string::npos ? std::string::npos : i - at));
    if (i == std::string::npos) return o;
    at = i + 1;
  }
}
}  // namespace

std::string CliSession::clean(const std::string& s) {
  std::string o;
  for (unsigned char c : s) o += c >= 0x20 && c < 0x7f ? static_cast<char>(c) : '?';
  return o.substr(0, 120);
}

std::string CliSession::reply(const StepResult& r) {
  switch (r.step) {
    case Step::Verified: return "OK";
    case Step::WrongCode: return "RETRY wrong code";
    case Step::Locked: return "LOCKED";
    case Step::Unreachable: return "UNREACHABLE";
    case Step::Unsupported: return "REJECT not supported here";
    default: return "REJECT " + clean(r.detail);
  }
}

bool CliSession::handle(const std::string& line, const Say& out) {
  auto p = words(line);
  const std::string& cmd = p[0];
  if (cmd == "BEGIN") {
    if (began_ || p.size() != 2 || !validService(p[1])) { out("DENY bad request"); return false; }
    began_ = true;
    if (isBreakGlass(cfg_, who_.domain, who_.user, who_.machine)) { out("ALLOW break-glass account"); allowed_ = true; return false; }
    if (mode_ == Mode::Passthrough) { out("ALLOW " + clean(why_)); allowed_ = true; return false; }
    if (mode_ == Mode::Broken || !gate_) { out("DENY " + clean(why_.empty() ? "Atlas is not usable on this PC" : why_)); return false; }
    GateDecision d;
    guard_([&] { d = gate_->begin(true); });  // the caller authenticated the user already (sshd / the logged-in session)
    if (d.kind == GateDecision::Kind::NotRequired) { out("ALLOW not required"); allowed_ = true; return false; }
    if (d.kind == GateDecision::Kind::Denied) { out("DENY " + clean(d.reason)); return false; }
    auto has = [&](const char* f) { return d.online && std::find(d.factors.begin(), d.factors.end(), f) != d.factors.end(); };
    push_ = has("push");
    totp_ = has("totp");
    offline_ = d.offlineAvailable;
    pin_ = d.offlinePinRequired;
    // A passkey needs the sign-in screen's window and a security-key prompt; a console cannot show that.
    if (!push_ && !totp_ && !offline_) { out("DENY no usable factor for a command line"); return false; }
    out(std::string("CHALLENGE online=") + (d.online ? "1" : "0") + " push=" + (push_ ? "1" : "0") + " totp=" + (totp_ ? "1" : "0") +
        " offline=" + (offline_ ? "1" : "0") + " pin=" + (pin_ ? "1" : "0"));
    return true;
  }
  if (cmd == "QUIT") return false;
  if (!began_ || mode_ != Mode::Gate || !gate_) { out("REJECT bad request"); return false; }
  if (cmd == "PUSH" && p.size() == 1 && push_) {
    StepResult s;
    guard_([&] { s = gate_->startPush(); });
    if (s.step != Step::Pending) { out(reply(s)); return true; }
    out("NUMBER " + clean(s.detail));
    for (int i = 0; i < maxPolls_; i++) {
      sleep_(2000);
      guard_([&] { s = gate_->pollPush(); });
      if (s.step == Step::Pending) continue;
      if (s.step == Step::Verified) allowed_ = true;
      out(reply(s));
      return true;
    }
    out("REJECT timed out");
    return true;
  }
  if (cmd == "CODE" && p.size() == 2 && totp_ && digits(p[1], 6, 6)) {
    StepResult s;
    guard_([&] { s = gate_->submitCode(p[1]); });
    allowed_ = allowed_ || s.step == Step::Verified;
    out(reply(s));
    return true;
  }
  if (cmd == "OFFLINE" && p.size() == 3 && offline_ && digits(p[2], 6, 6) && (p[1] == "-" || digits(p[1], 6, 12))) {
    StepResult s;
    guard_([&] { s = gate_->submitOffline(p[1] == "-" ? "" : p[1], p[2]); });
    allowed_ = allowed_ || s.step == Step::Verified;
    out(reply(s));
    return true;
  }
  out("REJECT bad request");
  return true;
}

// ---- console driver ----

bool cliAuthenticate(const CliIo& io, const std::string& service) {
  std::string line;
  if (!io.send("BEGIN " + service) || !io.recv(line, 45000)) return false;
  if (line.rfind("ALLOW", 0) == 0) return true;
  if (line.rfind("DENY", 0) == 0) { io.info("Sign-in refused: " + (line.size() > 5 ? line.substr(5) : std::string("denied"))); return false; }
  if (line.rfind("CHALLENGE ", 0) != 0) return false;
  auto flag = [&](const char* k) { return line.find(std::string(k) + "=1") != std::string::npos; };
  bool online = flag("online"), push = flag("push"), totp = flag("totp"), offline = flag("offline"), pin = flag("pin");
  auto numeric = [](const std::string& s) { return digits(s, 6, 12); };
  (void)online;

  if (push) {
    std::string r;
    if (io.send("PUSH") && io.recv(r, 45000) && r.rfind("NUMBER ", 0) == 0) {
      io.info("Approve the sign-in on your phone and pick the number " + r.substr(7));
      if (io.recv(r, 130000) && r == "OK") return true;
      io.info("Push was not approved.");
    }
  }
  if (totp) {
    for (int i = 0; i < 3; i++) {
      std::string code, r;
      if (!io.prompt("Authenticator code: ", false, code) || !digits(code, 6, 6)) { io.info("Enter the 6-digit code."); continue; }
      if (!io.send("CODE " + code) || !io.recv(r, 35000)) return false;
      if (r == "OK") return true;
      if (r == "UNREACHABLE") break;  // fall back to the offline code
      if (r.rfind("RETRY", 0) == 0) { io.info("That code was not accepted."); continue; }
      return false;
    }
  }
  if (offline) {
    for (int i = 0; i < 3; i++) {
      std::string p = "-", code, r;
      if (pin) {
        if (!io.prompt("Offline PIN: ", false, p) || !numeric(p)) { io.info("Enter your 6 to 12 digit PIN."); continue; }
      }
      if (!io.prompt("Offline authenticator code: ", false, code) || !digits(code, 6, 6)) { io.info("Enter the 6-digit code."); continue; }
      if (!io.send("OFFLINE " + p + " " + code) || !io.recv(r, 35000)) return false;
      if (r == "OK") return true;
      if (r.rfind("RETRY", 0) == 0) { io.info("PIN or code not accepted."); continue; }
      if (r == "LOCKED") io.info("Too many attempts: offline sign-in is locked for 15 minutes.");
      return false;
    }
  }
  return false;
}

}  // namespace atlas
