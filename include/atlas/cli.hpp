// Command-line MFA: the same LoginGate as the sign-in screen, behind a small line protocol (the macOS/Linux pam helper protocol,
// with the user taken from the authenticated pipe instead of the request), and the console driver that speaks it.
//
//   client -> service           service -> client
//   BEGIN <service>             ALLOW <text> | DENY <text> | CHALLENGE online=0|1 push=0|1 totp=0|1 offline=0|1 pin=0|1
//   PUSH                        NUMBER <digits>, then OK | REJECT <text> | UNREACHABLE
//   CODE <6 digits>             OK | RETRY <text> | REJECT <text> | LOCKED | UNREACHABLE
//   OFFLINE <pin|-> <6 digits>  OK | RETRY <text> | REJECT <text> | LOCKED
//   QUIT
#pragma once
#include "atlas/gate.hpp"
#include "atlas/policy.hpp"

#include <functional>

namespace atlas {

class CliSession {
 public:
  enum class Mode { Gate, Passthrough, Broken };
  struct Who { std::string domain, user, machine; };
  using Say = std::function<void(const std::string&)>;

  // `gate` is used in Mode::Gate only. `guard(fn)` runs fn under the caller's protocol lock (so a push poll can sleep outside it).
  CliSession(const Config& cfg, Mode mode, std::string why, LoginGate* gate, Who who, std::function<void(const std::function<void()>&)> guard,
             std::function<void(int)> sleepMs, int maxPolls = 60)
      : cfg_(cfg), mode_(mode), why_(std::move(why)), gate_(gate), who_(std::move(who)), guard_(std::move(guard)),
        sleep_(std::move(sleepMs)), maxPolls_(maxPolls) {}

  // One command line in, reply lines out. False when the session is over.
  bool handle(const std::string& line, const Say& out);
  bool allowed() const { return allowed_; }

 private:
  static std::string clean(const std::string& s);
  std::string reply(const StepResult& r);
  const Config& cfg_;
  Mode mode_;
  std::string why_;
  LoginGate* gate_;
  Who who_;
  std::function<void(const std::function<void()>&)> guard_;
  std::function<void(int)> sleep_;
  int maxPolls_;
  bool began_ = false, allowed_ = false, push_ = false, totp_ = false, offline_ = false, pin_ = false;
};

struct CliIo {
  std::function<bool(const std::string&)> send;                          // one command line
  std::function<bool(std::string&, int timeoutMs)> recv;                 // one reply line; false on timeout / closed
  std::function<void(const std::string&)> info;
  std::function<bool(const std::string&, bool echo, std::string&)> prompt;  // false = cancelled
};

// Drives the protocol on a console. True when the account may continue. Anything unexpected is a refusal.
bool cliAuthenticate(const CliIo& io, const std::string& service);

}  // namespace atlas
