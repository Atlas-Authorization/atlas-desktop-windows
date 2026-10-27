// Runs on a real Windows runner only. Microsoft does not publish a table of the in-box credential provider CLSIDs, so the
// registry the OS itself ships is the source of truth: every GUID this agent hides or keeps must be registered under the
// name we expect, or the test fails and the CI log shows what the machine has.
#include <gtest/gtest.h>

#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

#include "atlas/policy.hpp"
#include "webauthn_win.hpp"

namespace {
std::wstring regName(const wchar_t* guid) {
  std::wstring key = std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + guid;
  wchar_t buf[256] = {};
  DWORD n = sizeof buf - sizeof(wchar_t), type = 0;
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key.c_str(), nullptr, RRF_RT_REG_SZ, &type, buf, &n) != ERROR_SUCCESS) return L"";
  return buf;
}
std::string narrow(const std::wstring& w) {
  std::string s;
  for (wchar_t c : w) s.push_back(c < 128 ? static_cast<char>(c) : '?');
  return s;
}
}  // namespace

TEST(WindowsProviders, SmartCardGuidsAreTheOnesTheOsRegisters) {
  struct { const wchar_t* guid; const char* nameHas; } expected[] = {
      {L"{8FD7E19C-3BF7-489B-A72C-846AB3678C96}", "Smartcard Credential Provider"},
      {L"{1b283861-754f-4022-ad47-a5eaaa618894}", "Smartcard Reader Selection Provider"},
      {L"{1ee7337f-85ac-45e2-a23c-37c753209769}", "Smartcard WinRT Provider"},
      {L"{94596c7e-3744-41ce-893e-bbf09122f76a}", "Smartcard Pin Provider"},
  };
  for (auto& e : expected) {
    std::string name = narrow(regName(e.guid));
    std::printf("registered: %s = \"%s\"\n", narrow(e.guid).c_str(), name.c_str());
    EXPECT_NE(name.find(e.nameHas), std::string::npos) << narrow(e.guid) << " is registered as \"" << name << "\"";
    EXPECT_TRUE(atlas::isStockSmartCardProvider(narrow(e.guid)));
  }
}

TEST(WindowsProviders, PasswordTypeAndHelloGuidsMatchToo) {
  EXPECT_NE(narrow(regName(L"{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}")).find("Password"), std::string::npos);
  EXPECT_NE(narrow(regName(L"{cb82ea12-9f71-446d-89e1-8d0924e1256e}")).find("PIN"), std::string::npos);
  EXPECT_FALSE(regName(L"{D6886603-9D2F-4EB2-B667-1971041FA96B}").empty());  // NGC (Windows Hello for Business)
}

TEST(WindowsWebAuthn, LoadsWithoutPromptingAndFailsClosedWithoutAuthenticator) {
  win::WinWebAuthn w([] { return static_cast<HWND>(nullptr); });
  std::printf("webauthn platform API usable: %s\n", w.available() ? "yes" : "no");
  w.cancel();  // nothing in flight: must be a no-op
  // A request the parser rejects never reaches the platform (no prompt can appear on a CI runner).
  atlas::PasskeyRequest bad;
  std::string err;
  if (!w.available()) {
    EXPECT_FALSE(w.getAssertion(bad, "{}", err));
    EXPECT_EQ(err, "webauthn_unavailable");
  }
}
