// atlas-passkey.exe: register a security key as a passkey through this enrolled workstation (run elevated, in a signed-in session).
//   atlas-passkey.exe [--name <label>] [--factor totp|push] [--code <6 digits>]
// The key can then answer the passkey factor at sign-in. First the user passes another factor (the proof Atlas requires),
// then Windows shows its own security-key prompt. Codes are prompted for without echo.
#include "agent.hpp"
#include "webauthn_win.hpp"
#include "winutil.hpp"

#include <chrono>
#include <cstdio>
#include <iostream>
#include <thread>

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
  std::string name = "Security key", factor = "totp", code;
  for (int i = 1; i < argc; i++) {
    std::wstring a = argv[i];
    if (a == L"--name" && i + 1 < argc) name = win::toUtf8(argv[++i]);
    else if (a == L"--factor" && i + 1 < argc) factor = win::toUtf8(argv[++i]);
    else if (a == L"--code" && i + 1 < argc) code = win::toUtf8(argv[++i]);
    else { std::fprintf(stderr, "usage: atlas-passkey [--name LABEL] [--factor totp|push] [--code 123456]\n"); return 64; }
  }
  if (factor != "totp" && factor != "push") { std::fprintf(stderr, "--factor must be totp or push\n"); return 64; }

  std::shared_ptr<win::Agent> a;
  std::string why;
  if (win::loadAgent(a, why) != win::AgentState::Ready) { std::fprintf(stderr, "this workstation is not enrolled (%s)\n", why.c_str()); return 3; }
  win::WinWebAuthn webauthn([] { return GetConsoleWindow(); });
  if (!webauthn.available()) { std::fprintf(stderr, "this version of Windows has no WebAuthn platform support\n"); return 4; }

  std::lock_guard<std::mutex> g(a->mu);
  // Proof: a second factor passed on this workstation within the last five minutes.
  atlas::ApiResult s = a->client->startChallenge(factor);
  if (!s.ok() || !s.body.is_object() || !s.body.contains("id")) { std::fprintf(stderr, "could not start the verification (%s)\n", s.errorCode().c_str()); return 5; }
  std::string proof = s.body["id"];
  if (factor == "totp") {
    if (code.empty()) code = prompt("Code from your authenticator app");
    atlas::ApiResult v = a->client->verify(proof, code, std::nullopt);
    if (!v.ok() || v.body.value("status", "") != "verified") { std::fprintf(stderr, "that code was not accepted\n"); return 5; }
  } else {
    std::printf("Approve the request on your phone. Number to pick: %s\n", s.body.value("number_match", "").c_str());
    bool verified = false;
    for (int i = 0; i < 60 && !verified; i++) {
      std::this_thread::sleep_for(std::chrono::seconds(2));
      atlas::ApiResult v = a->client->verify(proof, std::nullopt, std::nullopt);
      std::string st = v.ok() ? v.body.value("status", "") : "error";
      if (st == "verified") verified = true;
      else if (st != "pending") break;
    }
    if (!verified) { std::fprintf(stderr, "the push was not approved\n"); return 5; }
  }

  std::printf("Touch your security key when Windows asks.\n");
  auto res = atlas::enrollPasskey(*a->client, webauthn, proof, name);
  if (!res.ok) { std::fprintf(stderr, "passkey registration failed: %s\n", res.error.c_str()); return 6; }
  std::printf("Passkey registered (%s).\n", res.passkeyId.c_str());
  return 0;
}
