// Atlas Login Agent: a credential provider that WRAPS the stock Windows password provider.
//
// The inner provider still draws the user tiles, the password box and builds the Kerberos/NTLM
// serialization. This wrapper adds the Atlas step and refuses to hand the serialization to LogonUI
// until atlas::LoginGate reports "satisfied". All decisions live in atlas_core; this file is UI glue.
//
// UNTESTED ON WINDOWS until CI runs: written without a Windows toolchain at hand.
#include "agent.hpp"
#include "guids.hpp"
#include "winutil.hpp"

#include <credentialprovider.h>
#include <shlwapi.h>
#include <wrl/client.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <thread>

using Microsoft::WRL::ComPtr;

HINSTANCE g_module = nullptr;
static std::atomic<long> g_objects{0};

BOOL APIENTRY DllMain(HINSTANCE h, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_module = h;
    DisableThreadLibraryCalls(h);
  }
  return TRUE;
}

namespace {

// ---- extra fields appended after the inner provider's own fields ----
enum Extra : DWORD { kStatus, kNumber, kCode, kPin, kPush, kOffline, kExtraCount };

HRESULT dup(PCWSTR s, PWSTR* out) { return SHStrDupW(s, out); }

bool has(const std::vector<std::string>& v, const char* f) {
  for (auto& x : v) if (x == f) return true;
  return false;
}

const wchar_t* denyText(const std::string& reason) {
  if (reason == "never_synced") return L"This PC has not synced with Atlas yet. Connect to the network and try again.";
  if (reason == "revoked") return L"This workstation was removed from Atlas. Contact your administrator.";
  if (reason == "no_factor") return L"No second factor is available. Contact your administrator.";
  if (reason == "offline_expired") return L"Offline sign-in has expired. Connect to the network.";
  if (reason == "clock") return L"The system clock looks wrong. Connect to the network to sync.";
  return L"Atlas can't be reached and no offline code is available.";
}

// ---- events proxy: the inner credential talks to LogonUI as if it were the wrapper ----
class EventsProxy final : public ICredentialProviderCredentialEvents2 {
 public:
  EventsProxy(ICredentialProviderCredential* owner, ICredentialProviderCredentialEvents* real) : owner_(owner), real_(real) {
    real_.As(&real2_);
  }
  IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredentialEvents) *ppv = static_cast<ICredentialProviderCredentialEvents*>(this);
    else if (riid == IID_ICredentialProviderCredentialEvents2 && real2_) *ppv = static_cast<ICredentialProviderCredentialEvents2*>(this);
    else { *ppv = nullptr; return E_NOINTERFACE; }
    AddRef();
    return S_OK;
  }
  IFACEMETHODIMP_(ULONG) AddRef() override { return ++ref_; }
  IFACEMETHODIMP_(ULONG) Release() override { ULONG r = --ref_; if (!r) delete this; return r; }

  IFACEMETHODIMP SetFieldState(ICredentialProviderCredential*, DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE s) override { return real_->SetFieldState(owner_, id, s); }
  IFACEMETHODIMP SetFieldInteractiveState(ICredentialProviderCredential*, DWORD id, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE s) override { return real_->SetFieldInteractiveState(owner_, id, s); }
  IFACEMETHODIMP SetFieldString(ICredentialProviderCredential*, DWORD id, LPCWSTR s) override { return real_->SetFieldString(owner_, id, s); }
  IFACEMETHODIMP SetFieldCheckbox(ICredentialProviderCredential*, DWORD id, BOOL c, LPCWSTR l) override { return real_->SetFieldCheckbox(owner_, id, c, l); }
  IFACEMETHODIMP SetFieldBitmap(ICredentialProviderCredential*, DWORD id, HBITMAP b) override { return real_->SetFieldBitmap(owner_, id, b); }
  IFACEMETHODIMP SetFieldComboBoxSelectedItem(ICredentialProviderCredential*, DWORD id, DWORD i) override { return real_->SetFieldComboBoxSelectedItem(owner_, id, i); }
  IFACEMETHODIMP DeleteFieldComboBoxItem(ICredentialProviderCredential*, DWORD id, DWORD i) override { return real_->DeleteFieldComboBoxItem(owner_, id, i); }
  IFACEMETHODIMP AppendFieldComboBoxItem(ICredentialProviderCredential*, DWORD id, LPCWSTR s) override { return real_->AppendFieldComboBoxItem(owner_, id, s); }
  IFACEMETHODIMP SetFieldSubmitButton(ICredentialProviderCredential*, DWORD id, DWORD adj) override { return real_->SetFieldSubmitButton(owner_, id, adj); }
  IFACEMETHODIMP OnCreatingWindow(HWND* h) override { return real_->OnCreatingWindow(h); }
  IFACEMETHODIMP BeginFieldUpdates() override { return real2_ ? real2_->BeginFieldUpdates() : E_NOTIMPL; }
  IFACEMETHODIMP EndFieldUpdates() override { return real2_ ? real2_->EndFieldUpdates() : E_NOTIMPL; }
  IFACEMETHODIMP SetFieldOptions(ICredentialProviderCredential*, DWORD id, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS o) override { return real2_ ? real2_->SetFieldOptions(owner_, id, o) : E_NOTIMPL; }

 private:
  std::atomic<ULONG> ref_{1};
  ICredentialProviderCredential* owner_;  // the wrapper; it outlives the proxy (UnAdvise precedes destruction)
  ComPtr<ICredentialProviderCredentialEvents> real_;
  ComPtr<ICredentialProviderCredentialEvents2> real2_;
};

// ---- the wrapping credential ----
class AtlasCredential final : public ICredentialProviderCredential2, public IConnectableCredentialProviderCredential {
 public:
  // agent == nullptr means "broken": enrolled but unusable, every submit is refused.
  AtlasCredential(ComPtr<ICredentialProviderCredential> inner, std::shared_ptr<win::Agent> agent, DWORD base)
      : inner_(std::move(inner)), agent_(std::move(agent)), base_(base) {
    ++g_objects;
    for (DWORD e = 0; e < kExtraCount; e++) states_[base_ + e] = {CPFS_HIDDEN, CPFIS_NONE};
    strings_[base_ + kPush] = L"Send push approval";
    strings_[base_ + kOffline] = L"Use offline code";
    if (agent_) gate_ = std::make_unique<atlas::LoginGate>(agent_->cfg, *agent_->client, *agent_->sync, *agent_->vault, agent_->store);
  }
  ~AtlasCredential() { requestStop(); joinPoll(); --g_objects; }

  // IUnknown
  IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential || riid == IID_ICredentialProviderCredential2)
      *ppv = static_cast<ICredentialProviderCredential2*>(this);
    else if (riid == IID_IConnectableCredentialProviderCredential) *ppv = static_cast<IConnectableCredentialProviderCredential*>(this);
    else { *ppv = nullptr; return E_NOINTERFACE; }
    AddRef();
    return S_OK;
  }
  IFACEMETHODIMP_(ULONG) AddRef() override { return ++ref_; }
  IFACEMETHODIMP_(ULONG) Release() override { ULONG r = --ref_; if (!r) delete this; return r; }

  // ICredentialProviderCredential
  IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* ev) override {
    { std::lock_guard<std::mutex> l(uiMu_); events_ = ev; }
    ComPtr<EventsProxy> proxy;
    proxy.Attach(new EventsProxy(self(), ev));
    return inner_->Advise(proxy.Get());
  }
  IFACEMETHODIMP UnAdvise() override {
    HRESULT hr = inner_->UnAdvise();
    std::lock_guard<std::mutex> l(uiMu_);
    events_.Reset();
    return hr;
  }
  IFACEMETHODIMP SetSelected(BOOL* autoLogon) override { return inner_->SetSelected(autoLogon); }
  IFACEMETHODIMP SetDeselected() override {
    resetFlow();
    return inner_->SetDeselected();
  }
  IFACEMETHODIMP GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* s, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* is) override {
    if (id < base_) return inner_->GetFieldState(id, s, is);
    std::lock_guard<std::mutex> l(uiMu_);
    auto it = states_.find(id);
    if (it == states_.end()) return E_INVALIDARG;
    *s = it->second.first;
    *is = it->second.second;
    return S_OK;
  }
  IFACEMETHODIMP GetStringValue(DWORD id, PWSTR* out) override {
    if (id < base_) return inner_->GetStringValue(id, out);
    std::lock_guard<std::mutex> l(uiMu_);
    auto it = strings_.find(id);
    return dup(it == strings_.end() ? L"" : it->second.c_str(), out);
  }
  IFACEMETHODIMP GetBitmapValue(DWORD id, HBITMAP* b) override { return id < base_ ? inner_->GetBitmapValue(id, b) : E_INVALIDARG; }
  IFACEMETHODIMP GetCheckboxValue(DWORD id, BOOL* c, PWSTR* l) override { return id < base_ ? inner_->GetCheckboxValue(id, c, l) : E_INVALIDARG; }
  IFACEMETHODIMP GetComboBoxValueCount(DWORD id, DWORD* n, DWORD* sel) override { return id < base_ ? inner_->GetComboBoxValueCount(id, n, sel) : E_INVALIDARG; }
  IFACEMETHODIMP GetComboBoxValueAt(DWORD id, DWORD i, PWSTR* s) override { return id < base_ ? inner_->GetComboBoxValueAt(id, i, s) : E_INVALIDARG; }
  IFACEMETHODIMP GetSubmitButtonValue(DWORD id, DWORD* adj) override { return id < base_ ? inner_->GetSubmitButtonValue(id, adj) : E_INVALIDARG; }
  IFACEMETHODIMP SetStringValue(DWORD id, PCWSTR s) override {
    if (id < base_) return inner_->SetStringValue(id, s);
    if (id != base_ + kCode && id != base_ + kPin) return E_INVALIDARG;
    std::lock_guard<std::mutex> l(uiMu_);
    strings_[id] = s ? s : L"";
    return S_OK;
  }
  IFACEMETHODIMP SetCheckboxValue(DWORD id, BOOL c) override { return id < base_ ? inner_->SetCheckboxValue(id, c) : E_INVALIDARG; }
  IFACEMETHODIMP SetComboBoxSelectedValue(DWORD id, DWORD i) override { return id < base_ ? inner_->SetComboBoxSelectedValue(id, i) : E_INVALIDARG; }
  IFACEMETHODIMP CommandLinkClicked(DWORD id) override {
    if (id < base_) return inner_->CommandLinkClicked(id);
    if (!agent_) return S_OK;
    if (id == base_ + kPush) {
      std::lock_guard<std::mutex> g(agent_->mu);
      if (prompted_ && !offlineMode_) startPushLocked();
    } else if (id == base_ + kOffline) {
      std::lock_guard<std::mutex> g(agent_->mu);
      if (prompted_ && decision_.offlineAvailable) { requestStop(); enterOfflineLocked(); }
    }
    return S_OK;
  }

  IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* resp, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* cs,
                                  PWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
    *resp = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *statusText = nullptr;
    *icon = CPSI_NONE;
    if (!agent_) {  // enrolled but unusable: fail closed, never hand out the password serialization
      *icon = CPSI_ERROR;
      dup(L"Atlas sign-in is not set up correctly on this PC. Contact your administrator.", statusText);
      return S_OK;
    }
    HRESULT hr;
    {
      std::lock_guard<std::mutex> g(agent_->mu);
      hr = serializeLocked(resp, cs, statusText, icon);
    }
    joinPoll();  // outside the lock: the poll thread never blocks on it, but keep the join lock-free anyway
    return hr;
  }

  IFACEMETHODIMP ReportResult(NTSTATUS st, NTSTATUS sub, PWSTR* text, CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
    HRESULT hr = inner_->ReportResult(st, sub, text, icon);
    resetFlow();
    return hr;
  }

  // ICredentialProviderCredential2
  IFACEMETHODIMP GetUserSid(PWSTR* sid) override {
    ComPtr<ICredentialProviderCredential2> c2;
    if (SUCCEEDED(inner_.As(&c2))) return c2->GetUserSid(sid);
    *sid = nullptr;
    return E_NOTIMPL;
  }

  // IConnectableCredentialProviderCredential
  IFACEMETHODIMP Connect(IQueryContinue* qc) override {
    ComPtr<IConnectableCredentialProviderCredential> c;
    return SUCCEEDED(inner_.As(&c)) ? c->Connect(qc) : S_OK;
  }
  IFACEMETHODIMP Disconnect() override {
    ComPtr<IConnectableCredentialProviderCredential> c;
    return SUCCEEDED(inner_.As(&c)) ? c->Disconnect() : S_OK;
  }

 private:
  ICredentialProviderCredential* self() { return static_cast<ICredentialProviderCredential*>(static_cast<ICredentialProviderCredential2*>(this)); }

  // ---- UI helpers (take only uiMu_, call LogonUI outside it) ----
  void setText(DWORD e, const std::wstring& t) {
    ComPtr<ICredentialProviderCredentialEvents> ev;
    {
      std::lock_guard<std::mutex> l(uiMu_);
      strings_[base_ + e] = t;
      ev = events_;
    }
    if (ev) ev->SetFieldString(self(), base_ + e, t.c_str());
  }
  void setShown(DWORD e, bool shown, bool focus = false) {
    CREDENTIAL_PROVIDER_FIELD_STATE s = shown ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE is = focus ? CPFIS_FOCUSED : CPFIS_NONE;
    ComPtr<ICredentialProviderCredentialEvents> ev;
    {
      std::lock_guard<std::mutex> l(uiMu_);
      states_[base_ + e] = {s, is};
      ev = events_;
    }
    if (ev) {
      ev->SetFieldState(self(), base_ + e, s);
      ev->SetFieldInteractiveState(self(), base_ + e, is);
    }
  }
  std::wstring text(DWORD e) {
    std::lock_guard<std::mutex> l(uiMu_);
    return strings_[base_ + e];
  }
  void hideAll() {
    for (DWORD e = 0; e < kExtraCount; e++) setShown(e, false);
    setText(kCode, L"");
    setText(kPin, L"");
    setText(kNumber, L"");
    setText(kStatus, L"");
  }
  void status(const wchar_t* s) { setText(kStatus, s); }

  // ---- flow (callers hold agent_->mu) ----
  void showPromptLocked() {
    const auto& d = decision_;
    bool totp = has(d.factors, "totp"), push = has(d.factors, "push");
    offlineMode_ = d.offlineAvailable && (!d.online || (!totp && !push));
    setShown(kStatus, true);
    setShown(kPush, push);
    setShown(kOffline, d.offlineAvailable && !offlineMode_);
    setShown(kCode, totp || offlineMode_, true);
    setShown(kPin, offlineMode_ && d.offlinePinRequired);
    status(offlineMode_ ? (d.offlinePinRequired ? L"Atlas can't be reached. Enter your PIN and the code from your authenticator app."
                                                 : L"Atlas can't be reached. Enter the code from your authenticator app.")
                        : L"Approve the sign-in on your phone, or enter a code, then sign in again.");
  }
  void enterOfflineLocked() {
    offlineMode_ = true;
    setShown(kNumber, false);
    setShown(kPush, false);
    setShown(kOffline, false);
    setShown(kCode, true, true);
    setShown(kPin, decision_.offlinePinRequired);
    status(decision_.offlinePinRequired ? L"Enter your PIN and the code from your authenticator app, then sign in."
                                        : L"Enter the code from your authenticator app, then sign in.");
  }
  void startPushLocked() {
    requestStop();
    joinPoll();
    atlas::StepResult r = gate_->startPush();
    if (r.step == atlas::Step::Pending) {
      setText(kNumber, win::toWide(r.detail));
      setShown(kNumber, true);
      status(L"Approve on your phone and pick the number shown below.");
      startPoll();
    } else {
      setShown(kNumber, false);
      status(r.step == atlas::Step::Unreachable ? L"Can't reach Atlas to send the push. Enter a code instead."
                                                : L"Push approval is not available. Enter a code instead.");
    }
  }

  HRESULT serializeLocked(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* resp, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* cs,
                          PWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* icon) {
    auto refuse = [&](const wchar_t* msg) {
      *resp = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
      *icon = CPSI_ERROR;
      status(msg);
      dup(msg, statusText);
      return S_OK;
    };
    if (!gate_->satisfied()) {
      if (!prompted_) {
        decision_ = gate_->begin();  // best-effort sync (bounded by the HTTP timeouts), then decide
        if (decision_.kind == atlas::GateDecision::Kind::Denied) {
          setShown(kStatus, true);
          return refuse(denyText(decision_.reason));
        }
        if (decision_.kind == atlas::GateDecision::Kind::Required) {
          prompted_ = true;
          showPromptLocked();
          if (!offlineMode_ && has(decision_.factors, "push")) startPushLocked();
          *icon = CPSI_WARNING;
          dup(L"Second factor required.", statusText);
          return S_OK;
        }
      } else {
        std::wstring code = text(kCode), pin = text(kPin);
        if (code.empty()) {
          *icon = CPSI_WARNING;
          dup(L"Approve the push on your phone, or enter a code.", statusText);
          return S_OK;
        }
        atlas::StepResult r = offlineMode_ ? gate_->submitOffline(win::toUtf8(pin), win::toUtf8(code)) : gate_->submitCode(win::toUtf8(code));
        setText(kCode, L"");
        setText(kPin, L"");
        switch (r.step) {
          case atlas::Step::Verified: break;
          case atlas::Step::WrongCode: return refuse(L"That code was not accepted.");
          case atlas::Step::Locked: return refuse(L"Too many wrong attempts. Try again in 15 minutes.");
          case atlas::Step::Unreachable:
            if (decision_.offlineAvailable) { enterOfflineLocked(); return refuse(L"Atlas can't be reached. Use an offline code."); }
            return refuse(L"Atlas can't be reached.");
          default: return refuse(L"Verification failed. Try again.");
        }
      }
    }
    if (!gate_->satisfied()) return refuse(L"Second factor required.");  // defensive: never fall through unverified
    // Verified (or not required): only now does the password serialization go out.
    HRESULT hr = inner_->GetSerialization(resp, cs, statusText, icon);
    requestStop();
    if (*resp == CPGSR_RETURN_CREDENTIAL_FINISHED) {  // one verification, one sign-in attempt
      gate_->reset();
      prompted_ = false;
      hideAll();
    }
    return hr;
  }

  void resetFlow() {
    requestStop();
    joinPoll();
    if (agent_) {
      std::lock_guard<std::mutex> g(agent_->mu);
      gate_->reset();
      prompted_ = false;
    }
    hideAll();
  }

  // ---- push poll thread; never blocks on agent_->mu so joins cannot deadlock ----
  void startPoll() {
    stop_ = false;
    thread_ = std::thread([this] { pollLoop(); });
  }
  void requestStop() {
    stop_ = true;
    cv_.notify_all();
  }
  void joinPoll() {
    if (thread_.joinable() && std::this_thread::get_id() != thread_.get_id()) thread_.join();
  }
  void pollLoop() {
    for (int i = 0; i < 150 && !stop_; i++) {  // 2 s apart, 5 minutes in total
      {
        std::unique_lock<std::mutex> l(pollMu_);
        cv_.wait_for(l, std::chrono::seconds(2), [this] { return stop_.load(); });
      }
      if (stop_) return;
      atlas::StepResult r;
      {
        std::unique_lock<std::mutex> g(agent_->mu, std::try_to_lock);
        if (!g.owns_lock()) continue;
        if (stop_) return;
        r = gate_->pollPush();
      }
      if (r.step == atlas::Step::Verified) {
        status(L"Approved. Press Enter or the arrow to sign in.");
        return;
      }
      if (r.step == atlas::Step::Failed) {
        setShown(kNumber, false);
        status(L"The push was denied or expired. Send a new push or enter a code.");
        return;
      }
    }
    if (!stop_) status(L"The push timed out. Send a new push or enter a code.");
  }

  std::atomic<ULONG> ref_{1};
  ComPtr<ICredentialProviderCredential> inner_;
  std::shared_ptr<win::Agent> agent_;
  DWORD base_;
  std::unique_ptr<atlas::LoginGate> gate_;  // guarded by agent_->mu
  atlas::GateDecision decision_;            // guarded by agent_->mu
  bool prompted_ = false, offlineMode_ = false;  // guarded by agent_->mu

  std::mutex uiMu_;
  ComPtr<ICredentialProviderCredentialEvents> events_;
  std::map<DWORD, std::pair<CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE>> states_;
  std::map<DWORD, std::wstring> strings_;

  std::thread thread_;
  std::atomic<bool> stop_{false};
  std::mutex pollMu_;
  std::condition_variable cv_;
};

// ---- the wrapping provider ----
class AtlasProvider final : public ICredentialProvider, public ICredentialProviderSetUserArray {
 public:
  AtlasProvider() { ++g_objects; }
  ~AtlasProvider() { --g_objects; }

  IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProvider) *ppv = static_cast<ICredentialProvider*>(this);
    else if (riid == IID_ICredentialProviderSetUserArray) *ppv = static_cast<ICredentialProviderSetUserArray*>(this);
    else { *ppv = nullptr; return E_NOINTERFACE; }
    AddRef();
    return S_OK;
  }
  IFACEMETHODIMP_(ULONG) AddRef() override { return ++ref_; }
  IFACEMETHODIMP_(ULONG) Release() override { ULONG r = --ref_; if (!r) delete this; return r; }

  IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD flags) override {
    HRESULT hr = CoCreateInstance(CLSID_StockPasswordProvider, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(inner_.ReleaseAndGetAddressOf()));
    if (FAILED(hr)) return hr;
    inner_.As(&innerUsers_);
    hr = inner_->SetUsageScenario(cpus, flags);
    if (FAILED(hr)) return hr;
    inner_->GetFieldDescriptorCount(&innerFields_);

    agent_.reset();
    wrapped_ = false;
    broken_ = false;
    // CredUI and password change keep behaving exactly like the stock provider; only sign-in and unlock are gated.
    if (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION) {
      std::string why;
      switch (win::loadAgent(agent_, why)) {
        case win::AgentState::Ready: wrapped_ = true; break;
        case win::AgentState::Broken: wrapped_ = broken_ = true; break;
        case win::AgentState::Passthrough: break;
      }
    }
    return S_OK;
  }
  IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* cs) override { return inner_ ? inner_->SetSerialization(cs) : E_UNEXPECTED; }
  IFACEMETHODIMP Advise(ICredentialProviderEvents* e, UINT_PTR ctx) override { return inner_ ? inner_->Advise(e, ctx) : E_UNEXPECTED; }
  IFACEMETHODIMP UnAdvise() override { return inner_ ? inner_->UnAdvise() : E_UNEXPECTED; }

  IFACEMETHODIMP GetFieldDescriptorCount(DWORD* n) override {
    if (!inner_) return E_UNEXPECTED;
    HRESULT hr = inner_->GetFieldDescriptorCount(n);
    if (SUCCEEDED(hr) && wrapped_) *n += kExtraCount;
    return hr;
  }
  IFACEMETHODIMP GetFieldDescriptorAt(DWORD i, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** pp) override {
    if (!inner_) return E_UNEXPECTED;
    if (i < innerFields_ || !wrapped_) return inner_->GetFieldDescriptorAt(i, pp);
    static const struct { CREDENTIAL_PROVIDER_FIELD_TYPE t; PCWSTR label; } defs[kExtraCount] = {
        {CPFT_SMALL_TEXT, L"Atlas status"},      {CPFT_LARGE_TEXT, L"Number to match"}, {CPFT_EDIT_TEXT, L"Authentication code"},
        {CPFT_PASSWORD_TEXT, L"Offline PIN"},    {CPFT_COMMAND_LINK, L"Send push approval"}, {CPFT_COMMAND_LINK, L"Use offline code"}};
    DWORD e = i - innerFields_;
    if (e >= kExtraCount) return E_INVALIDARG;
    auto* d = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (!d) return E_OUTOFMEMORY;
    d->dwFieldID = i;
    d->cpft = defs[e].t;
    d->guidFieldType = GUID_NULL;
    d->pszLabel = nullptr;
    if (FAILED(SHStrDupW(defs[e].label, &d->pszLabel))) { CoTaskMemFree(d); return E_OUTOFMEMORY; }
    *pp = d;
    return S_OK;
  }

  IFACEMETHODIMP GetCredentialCount(DWORD* n, DWORD* def, BOOL* autoLogon) override {
    if (!inner_) return E_UNEXPECTED;
    cache_.clear();
    return inner_->GetCredentialCount(n, def, autoLogon);
  }
  IFACEMETHODIMP GetCredentialAt(DWORD i, ICredentialProviderCredential** out) override {
    if (!inner_) return E_UNEXPECTED;
    if (!wrapped_) return inner_->GetCredentialAt(i, out);
    auto it = cache_.find(i);
    if (it != cache_.end()) { it->second.CopyTo(out); return S_OK; }
    ComPtr<ICredentialProviderCredential> c;
    HRESULT hr = inner_->GetCredentialAt(i, &c);
    if (FAILED(hr)) return hr;
    ComPtr<ICredentialProviderCredential> w;
    w.Attach(static_cast<ICredentialProviderCredential*>(static_cast<ICredentialProviderCredential2*>(
        new AtlasCredential(c, broken_ ? nullptr : agent_, innerFields_))));
    cache_[i] = w;
    w.CopyTo(out);
    return S_OK;
  }

  IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override { return innerUsers_ ? innerUsers_->SetUserArray(users) : S_OK; }

 private:
  std::atomic<ULONG> ref_{1};
  ComPtr<ICredentialProvider> inner_;
  ComPtr<ICredentialProviderSetUserArray> innerUsers_;
  std::shared_ptr<win::Agent> agent_;
  DWORD innerFields_ = 0;
  bool wrapped_ = false, broken_ = false;
  std::map<DWORD, ComPtr<ICredentialProviderCredential>> cache_;
};

class Factory final : public IClassFactory {
 public:
  IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
    if (riid == IID_IUnknown || riid == IID_IClassFactory) { *ppv = static_cast<IClassFactory*>(this); AddRef(); return S_OK; }
    *ppv = nullptr;
    return E_NOINTERFACE;
  }
  IFACEMETHODIMP_(ULONG) AddRef() override { return ++ref_; }
  IFACEMETHODIMP_(ULONG) Release() override { ULONG r = --ref_; if (!r) delete this; return r; }
  IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
    if (outer) return CLASS_E_NOAGGREGATION;
    ComPtr<AtlasProvider> p;
    p.Attach(new (std::nothrow) AtlasProvider());
    if (!p) return E_OUTOFMEMORY;
    return p->QueryInterface(riid, ppv);
  }
  IFACEMETHODIMP LockServer(BOOL lock) override { lock ? ++g_objects : --g_objects; return S_OK; }

 private:
  std::atomic<ULONG> ref_{1};
};

}  // namespace

STDAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void** ppv) {
  if (!ppv) return E_POINTER;
  *ppv = nullptr;
  if (clsid != CLSID_AtlasCredentialProvider) return CLASS_E_CLASSNOTAVAILABLE;
  ComPtr<Factory> f;
  f.Attach(new (std::nothrow) Factory());
  if (!f) return E_OUTOFMEMORY;
  return f->QueryInterface(riid, ppv);
}

STDAPI DllCanUnloadNow() { return g_objects.load() == 0 ? S_OK : S_FALSE; }
