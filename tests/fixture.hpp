#pragma once
#include "atlas/base.hpp"
#include "atlas/client.hpp"
#include "atlas/gate.hpp"
#include "atlas/offline.hpp"
#include "atlas/softkey.hpp"

#include <fstream>
#include <functional>
#include <set>
#include <sstream>

namespace t {
using namespace atlas;

inline const json& vectors() {
  static json v = [] {
    std::ifstream f(ATLAS_VECTORS_PATH);
    std::stringstream ss;
    ss << f.rdbuf();
    return json::parse(ss.str());
  }();
  return v;
}

struct TestClock : IClock {
  int64_t now = 1800000000000;  // == bundle issued_at; TOTP at this second is 877905
  int64_t nowMs() override { return now; }
};

inline Bundle vectorBundle() {
  const json& b = vectors()["bundle"];
  Bundle out;
  out.bundleId = b["bundle_id"];
  out.generation = b["generation"];
  out.expiresAt = b["expires_at"];
  out.issuedAt = b["plaintext"]["issued_at"];
  out.sealed = b["sealed"];
  out.mac = b["mac"];
  return out;
}

inline std::unique_ptr<SoftwareDeviceKey> vectorKey() { return SoftwareDeviceKey::fromPrivateJwk(vectors()["device_private_jwk"]); }

// Scripted server: handler gets the endpoint (e.g. "sync") and parsed body.
struct MockHttp : IHttpClient {
  struct Req { std::string path; json body; std::vector<std::pair<std::string, std::string>> headers; };
  std::function<HttpResponse(const std::string&, const json&)> handler;
  std::vector<Req> log;
  bool down = false;
  HttpResponse post(const std::string& url, const std::vector<std::pair<std::string, std::string>>& h,
                    const std::string& body) override {
    const std::string marker = "/v1/client/desktop_mfa/";
    auto p = url.find(marker);
    std::string path = p == std::string::npos ? url : url.substr(p + marker.size());
    json j = json::parse(body, nullptr, false);
    log.push_back({path, j, h});
    if (down) return {0, ""};
    return handler(path, j);
  }
  size_t count(const std::string& path) const {
    size_t n = 0;
    for (auto& r : log) n += r.path == path;
    return n;
  }
};

inline HttpResponse reply(int status, const json& j) { return {status, j.dump()}; }
}  // namespace t
