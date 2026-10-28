// IHttpClient over WinHTTP. HTTPS only; short timeouts because it runs on the sign-in screen.
#pragma once
#include "atlas/base.hpp"

namespace win {

class WinHttpClient : public atlas::IHttpClient {
 public:
  atlas::HttpResponse post(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers,
                           const std::string& body) override;
  atlas::HttpResponse get(const std::string& url, const std::vector<std::pair<std::string, std::string>>& headers) override;
};

}  // namespace win
