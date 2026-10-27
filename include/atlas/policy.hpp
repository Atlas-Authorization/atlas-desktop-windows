// Pure decisions the Windows glue relies on: stock-tile hiding, break-glass accounts, password-check classification.
#pragma once
#include "atlas/config.hpp"

#include <cstdint>

namespace atlas {

struct HideInputs {
  bool killSwitch = false;         // HKLM\SOFTWARE\Atlas\LoginAgent\Disabled
  bool enrolled = false;
  bool cacheKnown = false;         // a good sync has happened
  bool cacheRequired = false;      // ... and said MFA is required
  bool offlineBundleValid = false; // a usable offline bundle is held
  bool failClosedHide = false;     // config fail_closed_hide
};

// True when the filter should mark the stock password-type providers as not allowed.
// Fail-safe: anything uncertain leaves the stock tile visible, and a DLL that does not load cannot hide it at all.
bool shouldHideStockProvider(const HideInputs& in);

// Providers the filter hides (case-insensitive CLSID string with braces): password, picture password, PIN.
// Never matches the Atlas provider itself. Hello face/fingerprint and smart cards are strong factors of their own
// and are left alone.
bool isStockPasswordTypeProvider(const std::string& clsid, bool includeWindowsHello = false);

// Break-glass local account (config break_glass_accounts). An entry without a backslash matches only a local
// account (empty / "." / this machine as the domain); an entry "DOMAIN\name" must match exactly. Case-insensitive.
bool isBreakGlass(const Config& cfg, const std::string& domain, const std::string& user, const std::string& machineName);

enum class PasswordCheck { Verified, Wrong, Indeterminate };
// Maps a Win32 error from LogonUserW (0 = success). Errors that prove the password was right but block the
// logon (must change, expired, restrictions, logon type) count as Verified: stock Windows then explains them.
PasswordCheck classifyLogonUserError(uint32_t winError);
// Domain controller unreachable and similar: retry with an interactive logon, which can use cached credentials.
bool logonErrorNeedsInteractiveFallback(uint32_t winError);

}  // namespace atlas
