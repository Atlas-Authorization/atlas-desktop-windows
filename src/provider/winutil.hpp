// Thin Windows helpers. No protocol logic lives here.
#pragma once
#include <windows.h>

#include <optional>
#include <string>
#include <vector>

namespace win {

std::string toUtf8(const std::wstring& w);
std::wstring toWide(const std::string& s);

// %ProgramData%\Atlas
std::wstring dataDir();
std::wstring configPath();
// Creates the directory with an ACL limited to SYSTEM and Administrators.
bool ensureSecureDir(const std::wstring& path);
std::optional<std::vector<unsigned char>> readFile(const std::wstring& path);
bool writeFileAtomic(const std::wstring& path, const std::vector<unsigned char>& data);

// SSO broker pieces. The broker runs as the signed-in user, so its state lives under %LOCALAPPDATA% (DPAPI, current user)
// and it reads the instance settings from a copy of the config that every local user may read but only administrators may change.
std::wstring userDataDir();    // %LOCALAPPDATA%\Atlas\sso
std::wstring publicDir();      // %ProgramData%\Atlas-Public
std::wstring ssoConfigPath();  // publicDir()\sso.json : { instance_url, publishable_key, instance_id }
bool ensurePublicReadDir(const std::wstring& path);
bool ensureUserDir(const std::wstring& path);  // creates every missing level
std::wstring currentUserName();                // the Windows user name, no domain
std::wstring currentUserDomain();
std::wstring computerName();

// Reads one line from the console without echo (echo=false) or with it. False when there is no console to ask on.
bool readConsoleLine(const char* label, bool echo, std::string& out);

// HKLM\SOFTWARE\Atlas\LoginAgent : Disabled (REG_DWORD). Non-zero = pure pass-through to the stock password provider.
bool killSwitchOn();

}  // namespace win
