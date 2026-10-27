#include "atlas/config.hpp"

namespace atlas {

std::string Config::baseUrl() const {
  std::string u = instanceUrl;
  while (!u.empty() && u.back() == '/') u.pop_back();
  return u;
}

json Config::toJson() const {
  return {{"instance_url", instanceUrl}, {"publishable_key", publishableKey}, {"instance_id", instanceId},
          {"device_id", deviceId}, {"device_key_id", deviceKeyId}, {"seal_key_id", sealKeyId}, {"enrolled", enrolled},
          {"fail_open_when_never_synced", failOpenWhenNeverSynced}};
}

ConfigParse parseConfig(const std::string& text) {
  ConfigParse r;
  json j = json::parse(text, nullptr, false);
  if (j.is_discarded() || !j.is_object()) { r.error = "config is not a JSON object"; return r; }
  auto str = [&](const char* k, bool required, std::string& out) -> bool {
    if (!j.contains(k)) { if (required) { r.error = std::string("missing ") + k; return false; } return true; }
    if (!j[k].is_string()) { r.error = std::string(k) + " must be a string"; return false; }
    out = j[k];
    if (required && out.empty()) { r.error = std::string(k) + " is empty"; return false; }
    return true;
  };
  auto boolean = [&](const char* k, bool& out) -> bool {
    if (!j.contains(k)) return true;
    if (!j[k].is_boolean()) { r.error = std::string(k) + " must be a boolean"; return false; }
    out = j[k];
    return true;
  };
  Config c;
  if (!str("instance_url", true, c.instanceUrl) || !str("publishable_key", true, c.publishableKey) ||
      !str("instance_id", true, c.instanceId) || !str("device_id", false, c.deviceId) ||
      !str("device_key_id", false, c.deviceKeyId) || !str("seal_key_id", false, c.sealKeyId) || !boolean("enrolled", c.enrolled) ||
      !boolean("fail_open_when_never_synced", c.failOpenWhenNeverSynced))
    return r;
  if (c.instanceUrl.rfind("https://", 0) != 0 || c.instanceUrl.size() <= 8) { r.error = "instance_url must be an https:// URL"; return r; }
  if (c.enrolled && (c.deviceId.empty() || c.deviceKeyId.empty())) { r.error = "enrolled config needs device_id and device_key_id"; return r; }
  r.config = c;
  return r;
}

}  // namespace atlas
