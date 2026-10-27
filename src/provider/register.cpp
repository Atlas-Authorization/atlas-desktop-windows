// regsvr32 support: registers the COM class and the Credential Providers entry.
#include "guids.hpp"

#include <windows.h>

#include <string>

extern HINSTANCE g_module;

namespace {
bool setStr(HKEY root, const wchar_t* key, const wchar_t* name, const wchar_t* value) {
  return RegSetKeyValueW(root, key, name, REG_SZ, value, static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}
const wchar_t kClsidKey[] = L"SOFTWARE\\Classes\\CLSID\\" ATLAS_CLSID_STRING;
const wchar_t kFilterKey[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\" ATLAS_CLSID_STRING;
const wchar_t kEventKey[] = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\AtlasLoginAgent";
const wchar_t kCpKey[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\" ATLAS_CLSID_STRING;
}  // namespace

STDAPI DllRegisterServer() {
  wchar_t path[MAX_PATH];
  if (!GetModuleFileNameW(g_module, path, MAX_PATH)) return HRESULT_FROM_WIN32(GetLastError());
  std::wstring inproc = std::wstring(kClsidKey) + L"\\InprocServer32";
  bool ok = setStr(HKEY_LOCAL_MACHINE, kClsidKey, nullptr, ATLAS_PROVIDER_NAME) &&
            setStr(HKEY_LOCAL_MACHINE, inproc.c_str(), nullptr, path) &&
            setStr(HKEY_LOCAL_MACHINE, inproc.c_str(), L"ThreadingModel", L"Apartment") &&
            setStr(HKEY_LOCAL_MACHINE, kCpKey, nullptr, ATLAS_PROVIDER_NAME) &&
            setStr(HKEY_LOCAL_MACHINE, kFilterKey, nullptr, ATLAS_PROVIDER_NAME);
  // Event log source for break-glass audit events (generic message table from eventcreate.exe).
  const wchar_t msgFile[] = L"%SystemRoot%\\System32\\EventCreate.exe";
  DWORD types = 7;
  RegSetKeyValueW(HKEY_LOCAL_MACHINE, kEventKey, L"EventMessageFile", REG_EXPAND_SZ, msgFile, sizeof msgFile);
  RegSetKeyValueW(HKEY_LOCAL_MACHINE, kEventKey, L"TypesSupported", REG_DWORD, &types, sizeof types);
  return ok ? S_OK : SELFREG_E_CLASS;
}

STDAPI DllUnregisterServer() {
  RegDeleteTreeW(HKEY_LOCAL_MACHINE, kFilterKey);
  RegDeleteTreeW(HKEY_LOCAL_MACHINE, kEventKey);
  LSTATUS a = RegDeleteTreeW(HKEY_LOCAL_MACHINE, kCpKey);
  LSTATUS b = RegDeleteTreeW(HKEY_LOCAL_MACHINE, kClsidKey);
  auto okOrMissing = [](LSTATUS s) { return s == ERROR_SUCCESS || s == ERROR_FILE_NOT_FOUND; };
  return okOrMissing(a) && okOrMissing(b) ? S_OK : SELFREG_E_CLASS;
}
