#include "cli_pipe.hpp"

#include "winutil.hpp"

#include <sddl.h>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

namespace win {

PipeLine::~PipeLine() {
  if (h_ && h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
}

namespace {
// Waits for an overlapped operation; false on timeout (the operation is cancelled) or failure.
bool finish(HANDLE h, OVERLAPPED& ov, BOOL started, DWORD timeoutMs, DWORD& bytes) {
  if (!started && GetLastError() != ERROR_IO_PENDING) return false;
  if (!started) {
    if (WaitForSingleObject(ov.hEvent, timeoutMs) != WAIT_OBJECT_0) {
      CancelIoEx(h, &ov);
      GetOverlappedResult(h, &ov, &bytes, TRUE);
      return false;
    }
  }
  return GetOverlappedResult(h, &ov, &bytes, FALSE) != 0;
}
}  // namespace

bool PipeLine::readLine(std::string& out, DWORD timeoutMs) {
  for (;;) {
    auto nl = buf_.find('\n');
    if (nl != std::string::npos) {
      out = buf_.substr(0, nl);
      buf_.erase(0, nl + 1);
      if (!out.empty() && out.back() == '\r') out.pop_back();
      return out.size() < 256;
    }
    if (buf_.size() >= 256) return false;  // a line that long is not ours
    char tmp[256];
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DWORD got = 0;
    BOOL started = ReadFile(h_, tmp, static_cast<DWORD>(sizeof tmp), nullptr, &ov);
    bool ok = finish(h_, ov, started, timeoutMs, got);
    CloseHandle(ov.hEvent);
    if (!ok || got == 0) return false;
    buf_.append(tmp, got);
  }
}

bool PipeLine::writeLine(const std::string& line) {
  std::string data = line + "\n";
  OVERLAPPED ov{};
  ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  DWORD put = 0;
  BOOL started = WriteFile(h_, data.data(), static_cast<DWORD>(data.size()), nullptr, &ov);
  bool ok = finish(h_, ov, started, 10000, put);
  CloseHandle(ov.hEvent);
  return ok && put == data.size();
}

namespace {
bool identify(HANDLE pipe, atlas::CliSession::Who& who) {
  if (!ImpersonateNamedPipeClient(pipe)) return false;
  HANDLE tok = nullptr;
  bool ok = false;
  if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &tok)) {
    DWORD n = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &n);
    std::vector<unsigned char> buf(n);
    if (n && GetTokenInformation(tok, TokenUser, buf.data(), n, &n)) {
      wchar_t name[256] = {}, dom[256] = {};
      DWORD nl = 256, dl = 256;
      SID_NAME_USE use;
      if (LookupAccountSidW(nullptr, reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, name, &nl, dom, &dl, &use)) {
        who.user = toUtf8(name);
        who.domain = toUtf8(dom);
        who.machine = toUtf8(computerName());
        ok = true;
      }
    }
    CloseHandle(tok);
  }
  RevertToSelf();
  return ok;
}

void serveOne(HANDLE pipe, const HandlerFactory& factory) {
  PipeLine line(pipe);  // takes ownership of the handle
  // ImpersonateNamedPipeClient only works once the server has read from the pipe, so the first line comes before identify().
  std::string in;
  if (!line.readLine(in, 180000)) return;
  atlas::CliSession::Who who;
  if (!identify(pipe, who)) return;
  LineHandler handler = factory(who);
  bool alive = true;
  for (bool first = true; alive; first = false) {
    if (!first && !line.readLine(in, 180000)) break;  // idle, closed or garbage: the session ends and nothing was allowed
    bool write_ok = true;
    alive = handler(in, [&](const std::string& o) { write_ok = write_ok && line.writeLine(o); });
    if (!write_ok) break;
  }
  FlushFileBuffers(pipe);
  DisconnectNamedPipe(pipe);
}
}  // namespace

void servePipe(const std::wstring& name, const HandlerFactory& factory, HANDLE stop) {
  PSECURITY_DESCRIPTOR sd = nullptr;
  // SYSTEM and Administrators everything; any authenticated local user may talk on it. What a user may DO is decided per request.
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)", SDDL_REVISION_1, &sd, nullptr)) return;
  SECURITY_ATTRIBUTES sa{sizeof sa, sd, FALSE};
  auto active = std::make_shared<std::atomic<int>>(0);
  bool first = true;
  for (;;) {
    HANDLE pipe = CreateNamedPipeW(name.c_str(),
                                   PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
                                   PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES,
                                   4096, 4096, 0, &sa);
    if (pipe == INVALID_HANDLE_VALUE) break;
    first = false;
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOL c = ConnectNamedPipe(pipe, &ov);
    DWORD err = c ? 0 : GetLastError();
    bool connected = c || err == ERROR_PIPE_CONNECTED;
    if (!connected && err == ERROR_IO_PENDING) {
      HANDLE w[2] = {ov.hEvent, stop};
      DWORD r = WaitForMultipleObjects(2, w, FALSE, INFINITE);
      if (r == WAIT_OBJECT_0) connected = true;
      else { CancelIoEx(pipe, &ov); }
    }
    CloseHandle(ov.hEvent);
    if (!connected) { CloseHandle(pipe); break; }
    if (active->load() >= 16) { DisconnectNamedPipe(pipe); CloseHandle(pipe); continue; }
    active->fetch_add(1);
    std::thread([pipe, factory, active] {
      serveOne(pipe, factory);
      active->fetch_sub(1);
    }).detach();
  }
  LocalFree(sd);
}

HANDLE connectPipe(const std::wstring& name, DWORD waitMs, std::string& err) {
  for (int tries = 0; tries < 3; tries++) {
    HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (h != INVALID_HANDLE_VALUE) return h;
    DWORD e = GetLastError();
    if (e == ERROR_PIPE_BUSY) { WaitNamedPipeW(name.c_str(), waitMs); continue; }
    err = e == ERROR_FILE_NOT_FOUND ? "the Atlas MFA service is not running" : "cannot reach the Atlas MFA service (error " + std::to_string(e) + ")";
    return nullptr;
  }
  err = "the Atlas MFA service is busy";
  return nullptr;
}

}  // namespace win
