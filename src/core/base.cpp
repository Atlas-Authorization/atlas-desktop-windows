#include "atlas/base.hpp"

#include <chrono>

namespace atlas {

Bytes toBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }
std::string toString(const Bytes& b) { return std::string(b.begin(), b.end()); }

std::string b64uEncode(const Bytes& b) {
  static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  size_t i = 0;
  for (; i + 2 < b.size(); i += 3) {
    uint32_t v = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    out += t[v >> 18]; out += t[(v >> 12) & 63]; out += t[(v >> 6) & 63]; out += t[v & 63];
  }
  if (i + 1 == b.size()) {
    uint32_t v = b[i] << 16;
    out += t[v >> 18]; out += t[(v >> 12) & 63];
  } else if (i + 2 == b.size()) {
    uint32_t v = (b[i] << 16) | (b[i + 1] << 8);
    out += t[v >> 18]; out += t[(v >> 12) & 63]; out += t[(v >> 6) & 63];
  }
  return out;
}
std::string b64uEncode(const std::string& s) { return b64uEncode(toBytes(s)); }

std::optional<Bytes> b64uDecode(const std::string& s) {
  if (s.size() % 4 == 1) return std::nullopt;
  Bytes out;
  uint32_t acc = 0;
  int bits = 0;
  for (char c : s) {
    int v;
    if (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
    else if (c >= '0' && c <= '9') v = c - '0' + 52;
    else if (c == '-') v = 62;
    else if (c == '_') v = 63;
    else return std::nullopt;
    acc = (acc << 6) | static_cast<uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<uint8_t>((acc >> bits) & 0xff));
    }
  }
  return out;
}

std::optional<Bytes> base32Decode(const std::string& s) {
  Bytes out;
  uint32_t acc = 0;
  int bits = 0;
  for (char c : s) {
    if (c == '=' || c == ' ') continue;
    int v;
    if (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a';
    else if (c >= '2' && c <= '7') v = c - '2' + 26;
    else return std::nullopt;
    acc = (acc << 5) | static_cast<uint32_t>(v);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<uint8_t>((acc >> bits) & 0xff));
    }
  }
  return out;
}

bool ctEqual(const Bytes& a, const Bytes& b) {
  uint8_t d = static_cast<uint8_t>(a.size() != b.size());
  size_t n = a.size() < b.size() ? a.size() : b.size();
  for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
  return d == 0;
}
bool ctEqual(const std::string& a, const std::string& b) { return ctEqual(toBytes(a), toBytes(b)); }

std::optional<Bytes> MemorySecretStore::get(const std::string& name) {
  auto it = items.find(name);
  if (it == items.end()) return std::nullopt;
  return it->second;
}
bool MemorySecretStore::put(const std::string& name, const Bytes& value) { items[name] = value; return true; }
void MemorySecretStore::remove(const std::string& name) { items.erase(name); }

int64_t SystemClock::nowMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

std::optional<std::string> getString(ISecretStore& s, const std::string& name) {
  auto v = s.get(name);
  if (!v) return std::nullopt;
  return toString(*v);
}
bool putString(ISecretStore& s, const std::string& name, const std::string& v) { return s.put(name, toBytes(v)); }
std::optional<json> getJson(ISecretStore& s, const std::string& name) {
  auto v = getString(s, name);
  if (!v) return std::nullopt;
  auto j = json::parse(*v, nullptr, false);
  if (j.is_discarded()) return std::nullopt;
  return j;
}
bool putJson(ISecretStore& s, const std::string& name, const json& j) { return putString(s, name, j.dump()); }

}  // namespace atlas
