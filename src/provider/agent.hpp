// Everything the provider, enrol and sync tools share: config + key + store + client wiring.
#pragma once
#include "atlas/client.hpp"
#include "atlas/gate.hpp"
#include "dpapi_store.hpp"
#include "winhttp_client.hpp"
#include "winkey.hpp"

#include <memory>
#include <mutex>

namespace win {

struct Agent {
  atlas::Config cfg;
  DpapiStore store;
  atlas::SystemClock clock;
  WinHttpClient http;
  std::unique_ptr<CngDeviceKey> key;
  std::unique_ptr<atlas::Client> client;
  std::unique_ptr<atlas::OfflineVault> vault;
  std::unique_ptr<atlas::SyncService> sync;
  std::mutex mu;  // serialises protocol calls (UI thread and the push poll thread)
};

// Passthrough: not installed/enrolled or the kill switch is on - behave exactly like the stock provider.
// Ready: enrolled and healthy. Broken: enrolled but config/key unusable - the caller must fail closed.
enum class AgentState { Passthrough, Ready, Broken };

AgentState loadAgent(std::shared_ptr<Agent>& out, std::string& why);
// Reads and validates the config file only (used by the enrol tool).
atlas::ConfigParse readConfigFile();
bool writeConfigFile(const atlas::Config& c);
std::wstring keyNameFor(const atlas::Config& c);

}  // namespace win
