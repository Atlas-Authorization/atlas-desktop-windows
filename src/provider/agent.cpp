#include "agent.hpp"

#include "winutil.hpp"

namespace win {

atlas::ConfigParse readConfigFile() {
  auto f = readFile(configPath());
  if (!f) return {std::nullopt, "config file not found"};
  return atlas::parseConfig(std::string(f->begin(), f->end()));
}

bool writeConfigFile(const atlas::Config& c) {
  std::string text = c.toJson().dump(2);
  return ensureSecureDir(dataDir()) && writeFileAtomic(configPath(), std::vector<unsigned char>(text.begin(), text.end()));
}

std::wstring keyNameFor(const atlas::Config& c) { return L"AtlasLoginAgent-" + toWide(c.instanceId); }

AgentState loadAgent(std::shared_ptr<Agent>& out, std::string& why) {
  if (killSwitchOn()) { why = "disabled"; return AgentState::Passthrough; }
  auto raw = readFile(configPath());
  if (!raw) { why = "no config"; return AgentState::Passthrough; }  // installed but never configured
  auto parsed = atlas::parseConfig(std::string(raw->begin(), raw->end()));
  if (!parsed.config) { why = "invalid config: " + parsed.error; return AgentState::Broken; }
  if (!parsed.config->enrolled) { why = "not enrolled"; return AgentState::Passthrough; }
  auto a = std::make_shared<Agent>();
  a->cfg = *parsed.config;
  a->key = CngDeviceKey::open(toWide(a->cfg.deviceKeyId));
  if (!a->key) { why = "device key missing"; return AgentState::Broken; }
  a->client = std::make_unique<atlas::Client>(a->cfg, *a->key, a->http);
  a->vault = std::make_unique<atlas::OfflineVault>(a->store, a->clock, *a->key, a->cfg.deviceId);
  a->sync = std::make_unique<atlas::SyncService>(a->cfg, *a->client, *a->vault, a->store, a->clock);
  out = a;
  return AgentState::Ready;
}

}  // namespace win
