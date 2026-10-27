#pragma once
#include "atlas/base.hpp"

namespace atlas {

struct Config {
  std::string instanceUrl, publishableKey, instanceId, deviceId, deviceKeyId;
  std::string sealKeyId;  // optional second (ECDH) key label; empty = bundles are sealed to the signing key
  bool enrolled = false;
  bool failOpenWhenNeverSynced = false;

  std::string baseUrl() const;  // instance_url without a trailing slash
  json toJson() const;
};

struct ConfigParse {
  std::optional<Config> config;
  std::string error;
};
ConfigParse parseConfig(const std::string& text);

}  // namespace atlas
