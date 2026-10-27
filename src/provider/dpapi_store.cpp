#include "dpapi_store.hpp"

#include "winutil.hpp"

#include <wincrypt.h>

#include <cctype>

namespace win {
using atlas::Bytes;

namespace {
const char kEntropy[] = "atlas-login-agent-v1";
DATA_BLOB blobOf(const Bytes& b) { return {static_cast<DWORD>(b.size()), const_cast<BYTE*>(b.data())}; }
}  // namespace

DpapiStore::DpapiStore() : dir_(dataDir() + L"\\secrets") {}

std::wstring DpapiStore::pathFor(const std::string& name) const {
  std::string safe;
  for (char c : name) safe += (std::isalnum(static_cast<unsigned char>(c)) || c == '_') ? c : '_';
  return dir_ + L"\\" + toWide(safe) + L".bin";
}

std::optional<Bytes> DpapiStore::get(const std::string& name) {
  auto file = readFile(pathFor(name));
  if (!file) return std::nullopt;
  DATA_BLOB in = blobOf(*file), out{};
  Bytes entropy(kEntropy, kEntropy + sizeof kEntropy - 1);
  DATA_BLOB ent = blobOf(entropy);
  if (!CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return std::nullopt;
  Bytes res(out.pbData, out.pbData + out.cbData);
  SecureZeroMemory(out.pbData, out.cbData);
  LocalFree(out.pbData);
  return res;
}

bool DpapiStore::put(const std::string& name, const Bytes& value) {
  if (!ensureSecureDir(dataDir()) || !ensureSecureDir(dir_)) return false;
  DATA_BLOB in = blobOf(value), out{};
  Bytes entropy(kEntropy, kEntropy + sizeof kEntropy - 1);
  DATA_BLOB ent = blobOf(entropy);
  if (!CryptProtectData(&in, L"atlas", &ent, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &out))
    return false;
  bool ok = writeFileAtomic(pathFor(name), Bytes(out.pbData, out.pbData + out.cbData));
  LocalFree(out.pbData);
  return ok;
}

void DpapiStore::remove(const std::string& name) { DeleteFileW(pathFor(name).c_str()); }

}  // namespace win
