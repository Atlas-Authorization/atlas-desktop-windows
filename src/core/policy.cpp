#include "atlas/policy.hpp"

#include <algorithm>
#include <cctype>

namespace atlas {

namespace {
std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}
}  // namespace

bool shouldHideStockProvider(const HideInputs& in) {
  if (in.killSwitch || !in.enrolled) return false;
  if (in.cacheKnown) return in.cacheRequired;  // no MFA needed -> nothing to protect
  return in.failClosedHide || in.offlineBundleValid;
}

bool isStockPasswordTypeProvider(const std::string& clsid) {
  static const char* ids[] = {
      "{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}",  // password
      "{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}",  // picture password
      "{d6886603-9d3e-4db2-b1a1-00d83f2f8b8d}",  // PIN
  };
  std::string c = lower(clsid);
  for (const char* id : ids)
    if (c == id) return true;
  return false;
}

bool isBreakGlass(const Config& cfg, const std::string& domain, const std::string& user, const std::string& machine) {
  std::string u = lower(user), d = lower(domain), m = lower(machine);
  bool local = d.empty() || d == "." || d == m;
  for (const auto& entry : cfg.breakGlassAccounts) {
    std::string e = lower(entry);
    if (e.empty()) continue;
    if (e.find('\\') == std::string::npos) {
      if (local && e == u) return true;
    } else if (e == d + "\\" + u || (local && e == m + "\\" + u)) {
      return true;
    }
  }
  return false;
}

bool logonErrorNeedsInteractiveFallback(uint32_t e) {
  switch (e) {
    case 1311:  // ERROR_NO_LOGON_SERVERS
    case 1355:  // ERROR_NO_SUCH_DOMAIN
    case 1722:  // RPC_S_SERVER_UNAVAILABLE
    case 1787:  // ERROR_NO_TRUST_SAM_ACCOUNT
    case 1789:  // ERROR_TRUSTED_RELATIONSHIP_FAILURE
      return true;
    default: return false;
  }
}

PasswordCheck classifyLogonUserError(uint32_t e) {
  switch (e) {
    case 0:
    case 1327:  // ERROR_ACCOUNT_RESTRICTION
    case 1328:  // ERROR_INVALID_LOGON_HOURS
    case 1329:  // ERROR_INVALID_WORKSTATION
    case 1330:  // ERROR_PASSWORD_EXPIRED
    case 1385:  // ERROR_LOGON_TYPE_NOT_GRANTED
    case 1907:  // ERROR_PASSWORD_MUST_CHANGE
      return PasswordCheck::Verified;
    case 1326:  // ERROR_LOGON_FAILURE
    case 1331:  // ERROR_ACCOUNT_DISABLED
    case 1909:  // ERROR_ACCOUNT_LOCKED_OUT
      return PasswordCheck::Wrong;
    default: return PasswordCheck::Indeterminate;
  }
}

}  // namespace atlas
