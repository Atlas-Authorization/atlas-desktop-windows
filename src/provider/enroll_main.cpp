// atlas-enroll.exe: run once, elevated, after the MSI is installed.
//   atlas-enroll.exe [--code <enrolment code>] [--pin <6-12 digits>] [--show-otp-uri] [--force]
//   atlas-enroll.exe --write-config --instance-url U --publishable-key K --instance-id I [--fail-open]
//     (run by the MSI: creates config.json unless an enrolled one already exists)
// Missing --code / --pin are prompted for without echo (a command line is visible to other processes).
#include "agent.hpp"
#include "winutil.hpp"

#include <cstdio>
#include <iostream>

namespace {
std::string prompt(const char* label) {
  std::printf("%s: ", label);
  std::fflush(stdout);
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  bool console = GetConsoleMode(in, &mode) != 0;
  if (console) SetConsoleMode(in, mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
  std::string s;
  std::getline(std::cin, s);
  if (console) { SetConsoleMode(in, mode); std::printf("\n"); }
  while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
  return s;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  std::string code, pin, url, pk, iid;
  bool showUri = false, force = false, writeConfig = false, failOpen = false;
  for (int i = 1; i < argc; i++) {
    std::wstring a = argv[i];
    if (a == L"--write-config") writeConfig = true;
    else if (a == L"--instance-url" && i + 1 < argc) url = win::toUtf8(argv[++i]);
    else if (a == L"--publishable-key" && i + 1 < argc) pk = win::toUtf8(argv[++i]);
    else if (a == L"--instance-id" && i + 1 < argc) iid = win::toUtf8(argv[++i]);
    else if (a == L"--fail-open") failOpen = true;
    else if (a == L"--code" && i + 1 < argc) code = win::toUtf8(argv[++i]);
    else if (a == L"--pin" && i + 1 < argc) pin = win::toUtf8(argv[++i]);
    else if (a == L"--show-otp-uri") showUri = true;
    else if (a == L"--force") force = true;
    else { std::fprintf(stderr, "usage: atlas-enroll [--code C] [--pin P] [--show-otp-uri] [--force]\n"); return 64; }
  }
  if (writeConfig) {
    auto existing = win::readConfigFile();
    if (existing.config && existing.config->enrolled) { std::printf("config already enrolled, left untouched\n"); return 0; }
    atlas::Config c;
    c.instanceUrl = url;
    c.publishableKey = pk;
    c.instanceId = iid;
    c.failOpenWhenNeverSynced = failOpen;
    auto check = atlas::parseConfig(c.toJson().dump());
    if (!check.config) { std::fprintf(stderr, "config error: %s\n", check.error.c_str()); return 2; }
    if (!win::writeConfigFile(c)) { std::fprintf(stderr, "could not write the config file\n"); return 6; }
    std::printf("config written\n");
    return 0;
  }
  auto parsed = win::readConfigFile();
  if (!parsed.config) { std::fprintf(stderr, "config error: %s\n", parsed.error.c_str()); return 2; }
  atlas::Config cfg = *parsed.config;
  if (cfg.enrolled && !force) { std::fprintf(stderr, "already enrolled (use --force to enrol again)\n"); return 3; }
  if (code.empty()) code = prompt("Enrolment code");
  if (pin.empty()) pin = prompt("Offline PIN (6-12 digits, empty if your policy has none)");
  if (code.empty()) { std::fprintf(stderr, "an enrolment code is required\n"); return 64; }

  std::wstring keyName = win::keyNameFor(cfg);
  bool hardware = false;
  std::string err;
  auto key = win::CngDeviceKey::create(keyName, hardware, err);
  if (!key) { std::fprintf(stderr, "could not create the device key (%s)\n", err.c_str()); return 4; }

  wchar_t host[MAX_COMPUTERNAME_LENGTH + 1] = {};
  DWORD hl = MAX_COMPUTERNAME_LENGTH + 1;
  GetComputerNameW(host, &hl);

  win::DpapiStore store;
  win::WinHttpClient http;
  auto res = atlas::enrollDevice(cfg, *key, http, store, code, pin, win::toUtf8(host), "windows", "0.1.0");
  if (!res.ok) {
    key->deleteKey();
    std::fprintf(stderr, "enrolment failed: %s\n", res.error.c_str());
    return 5;
  }
  cfg.deviceKeyId = win::toUtf8(keyName);
  if (!win::writeConfigFile(cfg)) { std::fprintf(stderr, "enrolled, but the config file could not be written\n"); return 6; }
  std::printf("Enrolled. Device key is %s.\n", hardware ? "held in the TPM" : "held in the software key store (no TPM key available)");
  if (showUri && !res.offlineOtpUri.empty())
    std::printf("Offline authenticator URI (shown once, add it to your authenticator app):\n%s\n", res.offlineOtpUri.c_str());

  win::AgentState st;
  std::shared_ptr<win::Agent> a;
  std::string why;
  st = win::loadAgent(a, why);
  if (st == win::AgentState::Ready) {
    std::lock_guard<std::mutex> g(a->mu);
    std::printf("First sync: %s\n", a->sync->run() == atlas::SyncOutcome::Ok ? "ok" : "failed (the scheduled task will retry)");
  }
  return 0;
}
