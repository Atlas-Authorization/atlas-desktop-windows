#include "winhttp_client.hpp"

#include "winutil.hpp"

#include <winhttp.h>

namespace win {

namespace {
struct Handle {
  HINTERNET h = nullptr;
  explicit Handle(HINTERNET x = nullptr) : h(x) {}
  ~Handle() { if (h) WinHttpCloseHandle(h); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
};
constexpr size_t kMaxResponse = 1 << 20;
}  // namespace

atlas::HttpResponse WinHttpClient::post(const std::string& url,
                                        const std::vector<std::pair<std::string, std::string>>& headers,
                                        const std::string& body) {
  std::wstring wurl = toWide(url);
  URL_COMPONENTS uc{};
  uc.dwStructSize = sizeof uc;
  uc.dwSchemeLength = uc.dwHostNameLength = uc.dwUrlPathLength = uc.dwExtraInfoLength = static_cast<DWORD>(-1);
  if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc) || uc.nScheme != INTERNET_SCHEME_HTTPS)
    return {};  // plain HTTP is never used
  std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
  std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength + uc.dwExtraInfoLength);

  Handle session(WinHttpOpen(L"AtlasLoginAgent/0.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                             WINHTTP_NO_PROXY_BYPASS, 0));
  if (!session.h)
    session.h = WinHttpOpen(L"AtlasLoginAgent/0.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                            WINHTTP_NO_PROXY_BYPASS, 0);
  if (!session.h) return {};
  WinHttpSetTimeouts(session.h, 3000, 3000, 8000, 8000);
  DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | 0x00002000 /* TLS1.3 where supported */;
  WinHttpSetOption(session.h, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof protocols);

  Handle conn(WinHttpConnect(session.h, host.c_str(), uc.nPort, 0));
  if (!conn.h) return {};
  Handle req(WinHttpOpenRequest(conn.h, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                WINHTTP_FLAG_SECURE));
  if (!req.h) return {};
  std::wstring hdr;
  for (auto& h : headers) hdr += toWide(h.first) + L": " + toWide(h.second) + L"\r\n";
  if (!WinHttpSendRequest(req.h, hdr.c_str(), static_cast<DWORD>(hdr.size()), const_cast<char*>(body.data()),
                          static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0) ||
      !WinHttpReceiveResponse(req.h, nullptr))
    return {};
  DWORD status = 0, sz = sizeof status;
  if (!WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status,
                           &sz, WINHTTP_NO_HEADER_INDEX))
    return {};
  atlas::HttpResponse out;
  out.status = static_cast<int>(status);
  for (;;) {
    DWORD avail = 0;
    if (!WinHttpQueryDataAvailable(req.h, &avail)) return {};
    if (avail == 0) break;
    if (out.body.size() + avail > kMaxResponse) return {};
    size_t at = out.body.size();
    out.body.resize(at + avail);
    DWORD got = 0;
    if (!WinHttpReadData(req.h, &out.body[at], avail, &got)) return {};
    out.body.resize(at + got);
  }
  return out;
}

}  // namespace win
