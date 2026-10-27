#include "winutil.hpp"

#include <sddl.h>
#include <shlobj.h>

namespace win {

std::string toUtf8(const std::wstring& w) {
  if (w.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  std::string s(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
  return s;
}

std::wstring toWide(const std::string& s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(static_cast<size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
  return w;
}

std::wstring dataDir() {
  PWSTR p = nullptr;
  std::wstring base = L"C:\\ProgramData";
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &p)) && p) base = p;
  CoTaskMemFree(p);
  return base + L"\\Atlas";
}

std::wstring configPath() { return dataDir() + L"\\config.json"; }

bool ensureSecureDir(const std::wstring& path) {
  SECURITY_ATTRIBUTES sa{sizeof sa, nullptr, FALSE};
  PSECURITY_DESCRIPTOR sd = nullptr;
  // Full control for SYSTEM and Administrators only; inherited by children.
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1,
                                                            &sd, nullptr))
    return false;
  sa.lpSecurityDescriptor = sd;
  BOOL ok = CreateDirectoryW(path.c_str(), &sa) || GetLastError() == ERROR_ALREADY_EXISTS;
  LocalFree(sd);
  return ok != FALSE;
}

std::optional<std::vector<unsigned char>> readFile(const std::wstring& path) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return std::nullopt;
  LARGE_INTEGER sz{};
  std::vector<unsigned char> buf;
  if (GetFileSizeEx(h, &sz) && sz.QuadPart >= 0 && sz.QuadPart < (16 << 20)) {
    buf.resize(static_cast<size_t>(sz.QuadPart));
    DWORD got = 0;
    if (!buf.empty() && (!ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr) || got != buf.size())) {
      CloseHandle(h);
      return std::nullopt;
    }
  } else {
    CloseHandle(h);
    return std::nullopt;
  }
  CloseHandle(h);
  return buf;
}

bool writeFileAtomic(const std::wstring& path, const std::vector<unsigned char>& data) {
  std::wstring tmp = path + L".tmp";
  HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  DWORD put = 0;
  bool ok = (data.empty() || WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &put, nullptr)) && put == data.size() &&
            FlushFileBuffers(h);
  CloseHandle(h);
  if (ok) ok = MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
  if (!ok) DeleteFileW(tmp.c_str());
  return ok;
}

bool killSwitchOn() {
  DWORD v = 0, sz = sizeof v;
  if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Atlas\\LoginAgent", L"Disabled", RRF_RT_REG_DWORD, nullptr, &v, &sz) ==
      ERROR_SUCCESS)
    return v != 0;
  return false;
}

}  // namespace win
