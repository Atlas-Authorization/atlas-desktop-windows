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

// HKLM\SOFTWARE\Atlas\LoginAgent : Disabled (REG_DWORD). Non-zero = pure pass-through to the stock password provider.
bool killSwitchOn();

}  // namespace win
