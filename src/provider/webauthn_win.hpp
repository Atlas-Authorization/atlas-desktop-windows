// WebAuthn through the platform API (webauthn.dll), loaded at run time so this DLL still loads on a Windows without it
// (a credential provider that fails to load must never take the sign-in screen down with it).
// API: https://github.com/microsoft/webauthn (webauthn.h, WebAuthNAuthenticatorGetAssertion / MakeCredential).
#pragma once
#include "atlas/passkey.hpp"

#include <windows.h>

#include <atomic>
#include <functional>
#include <mutex>

namespace win {

class WinWebAuthn final : public atlas::IPasskeyAuthenticator {
 public:
  // `owner` supplies the window the platform UI is parented to (LogonUI's, from OnCreatingWindow). May return null.
  using OwnerFn = std::function<HWND()>;
  explicit WinWebAuthn(OwnerFn owner = nullptr) : owner_(std::move(owner)) {}

  bool available() override;
  std::optional<atlas::RawAssertion> getAssertion(const atlas::PasskeyRequest& req, const std::string& clientData, std::string& err) override;
  std::optional<atlas::RawAttestation> makeCredential(const atlas::PasskeyCreation& req, const std::string& clientData, std::string& err) override;
  void cancel() override;

 private:
  HWND ownerWindow() const;
  OwnerFn owner_;
  std::mutex mu_;
  GUID cancelId_{};
  std::atomic<bool> active_{false};
};

}  // namespace win
