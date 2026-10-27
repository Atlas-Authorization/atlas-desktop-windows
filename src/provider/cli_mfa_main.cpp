// atlas-cli-mfa.exe: second factor for command lines (OpenSSH for Windows, PowerShell sessions, scripts that ask for it).
//   atlas-cli-mfa.exe check [--service NAME] [--user NAME]   asks for the factor on the console; exit 0 = allowed
//   atlas-cli-mfa.exe ssh-wrap                               sshd ForceCommand: factor first, then the user's real command or shell
//   atlas-cli-mfa.exe service                                run by the Service Control Manager (service "AtlasCliMfa", LocalSystem)
//   atlas-cli-mfa.exe serve                                  the same in a console (testing)
// The clients hold no keys: they talk over a named pipe to the service, which holds the device keys, the offline bundle and the config
// (all readable only by SYSTEM / Administrators) and runs the same LoginGate as the sign-in screen. Exit codes: 0 allowed, 1 refused,
// 2 service unreachable / broken (refused), 64 usage.
#include "agent.hpp"
#include "cli_pipe.hpp"
#include "winutil.hpp"

#include <cstdio>
#include <cwctype>
#include <memory>
#include <mutex>
#include <vector>
#include <wchar.h>

namespace {
const wchar_t* kServiceName = L"AtlasCliMfa";
HANDLE g_stop = nullptr;
SERVICE_STATUS_HANDLE g_status = nullptr;

// ---- service side ----

win::LineHandler makeHandler(const atlas::CliSession::Who& who) {
  struct State {
    std::shared_ptr<win::Agent> agent;
    std::unique_ptr<atlas::LoginGate> gate;
    std::unique_ptr<atlas::CliSession> session;
  };
  auto st = std::make_shared<State>();
  std::string why;
  win::AgentState a = win::loadAgent(st->agent, why);
  atlas::CliSession::Mode mode = a == win::AgentState::Ready ? atlas::CliSession::Mode::Gate
                                 : a == win::AgentState::Passthrough ? atlas::CliSession::Mode::Passthrough
                                                                     : atlas::CliSession::Mode::Broken;
  static const atlas::Config kEmpty{};
  const atlas::Config& cfg = st->agent ? st->agent->cfg : kEmpty;
  if (st->agent) {
    auto& ag = *st->agent;
    st->gate = std::make_unique<atlas::LoginGate>(ag.cfg, *ag.client, *ag.sync, *ag.vault, ag.store);
  }
  // Without a loaded agent break-glass cannot be consulted (no config): Passthrough/Broken decide on their own.
  // Every connection loads its own agent, so the protocol lock is global: two sessions never sync or poll at the same moment.
  static std::mutex protocolMu;
  auto guard = [st](const std::function<void()>& fn) {
    std::lock_guard<std::mutex> g(protocolMu);
    fn();
  };
  st->session = std::make_unique<atlas::CliSession>(cfg, mode, why, st->gate.get(), who, guard, [](int ms) { Sleep(static_cast<DWORD>(ms)); });
  return [st](const std::string& line, const atlas::CliSession::Say& say) { return st->session->handle(line, say); };
}

DWORD WINAPI ctrlHandler(DWORD ctl, DWORD, LPVOID, LPVOID) {
  if (ctl == SERVICE_CONTROL_STOP || ctl == SERVICE_CONTROL_SHUTDOWN) {
    SERVICE_STATUS s{SERVICE_WIN32_OWN_PROCESS, SERVICE_STOP_PENDING, 0, 0, 0, 1, 5000};
    SetServiceStatus(g_status, &s);
    SetEvent(g_stop);
    return NO_ERROR;
  }
  return ctl == SERVICE_CONTROL_INTERROGATE ? NO_ERROR : ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI serviceMain(DWORD, LPWSTR*) {
  g_status = RegisterServiceCtrlHandlerExW(kServiceName, ctrlHandler, nullptr);
  if (!g_status) return;
  SERVICE_STATUS run{SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, 0, 0, 0, 0};
  SetServiceStatus(g_status, &run);
  win::servePipe(win::kCliPipe, makeHandler, g_stop);
  SERVICE_STATUS done{SERVICE_WIN32_OWN_PROCESS, SERVICE_STOPPED, 0, 0, 0, 0, 0};
  SetServiceStatus(g_status, &done);
}

// ---- client side ----

// Talks to the service. 0 allowed, 1 refused, 2 service unreachable.
int askService(const std::string& service) {
  if (win::killSwitchOn()) { std::fprintf(stderr, "Atlas MFA is switched off on this PC (kill switch); continuing without it.\n"); return 0; }
  std::string err;
  HANDLE h = win::connectPipe(win::kCliPipe, 5000, err);
  if (!h) { std::fprintf(stderr, "Atlas MFA: %s. Refusing.\n", err.c_str()); return 2; }
  win::PipeLine pipe(h);
  atlas::CliIo io;
  io.send = [&](const std::string& l) { return pipe.writeLine(l); };
  io.recv = [&](std::string& out, int ms) { return pipe.readLine(out, static_cast<DWORD>(ms)); };
  io.info = [](const std::string& m) { std::fprintf(stderr, "%s\n", m.c_str()); };
  io.prompt = [](const std::string& label, bool echo, std::string& out) { return win::readConsoleLine(label.c_str(), echo, out); };
  bool ok = atlas::cliAuthenticate(io, service);
  pipe.writeLine("QUIT");
  return ok ? 0 : 1;
}

std::wstring shellFor(bool& isPowerShell, bool& isCmd) {
  wchar_t buf[MAX_PATH] = {};
  DWORD n = sizeof buf;
  std::wstring shell;
  if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\OpenSSH", L"DefaultShell", RRF_RT_REG_SZ, nullptr, buf, &n) == ERROR_SUCCESS) shell = buf;
  if (shell.empty() && GetEnvironmentVariableW(L"ComSpec", buf, MAX_PATH)) shell = buf;
  if (shell.empty()) shell = L"C:\\Windows\\System32\\cmd.exe";
  std::wstring low;
  for (wchar_t c : shell) low += static_cast<wchar_t>(towlower(c));
  isPowerShell = low.find(L"powershell.exe") != std::wstring::npos || low.find(L"pwsh.exe") != std::wstring::npos;
  isCmd = low.find(L"cmd.exe") != std::wstring::npos;
  return shell;
}

// Runs what the user asked for, after the factor passed. The command string comes from sshd's environment and goes only to the shell.
int runUserCommand() {
  bool ps = false, cmd = false;
  std::wstring shell = shellFor(ps, cmd);
  wchar_t orig[8192] = {};
  DWORD n = GetEnvironmentVariableW(L"SSH_ORIGINAL_COMMAND", orig, 8192);
  std::wstring line = L"\"" + shell + L"\"";
  if (n > 0 && n < 8192) line += (ps ? L" -NoLogo -Command " : cmd ? L" /s /c \"" : L" -c ") + std::wstring(orig) + (cmd ? L"\"" : L"");
  else if (ps) line += L" -NoLogo";
  STARTUPINFOW si{sizeof si};
  PROCESS_INFORMATION pi{};
  std::vector<wchar_t> mut(line.begin(), line.end());
  mut.push_back(0);
  if (!CreateProcessW(shell.c_str(), mut.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
    std::fprintf(stderr, "Atlas MFA: cannot start the shell (error %lu)\n", GetLastError());
    return 126;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return static_cast<int>(code);
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  std::wstring mode = argc > 1 ? argv[1] : L"";
  if (mode == L"service") {
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(kServiceName), serviceMain}, {nullptr, nullptr}};
    return StartServiceCtrlDispatcherW(table) ? 0 : 2;
  }
  if (mode == L"serve") {
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler([](DWORD) -> BOOL { SetEvent(g_stop); return TRUE; }, TRUE);
    std::printf("atlas-cli-mfa: serving %ls (Ctrl+C stops)\n", win::kCliPipe);
    win::servePipe(win::kCliPipe, makeHandler, g_stop);
    return 0;
  }
  if (mode == L"check" || mode == L"ssh-wrap") {
    std::string service = mode == L"ssh-wrap" ? "sshd" : "cli";
    for (int i = 2; i < argc; i++) {
      std::wstring a = argv[i];
      if (a == L"--service" && i + 1 < argc) service = win::toUtf8(argv[++i]);
      else if (a == L"--user" && i + 1 < argc) {
        // The service decides by who is on the pipe. A different name here is a mistake or an attempt; refuse either way.
        if (_wcsicmp(argv[++i], win::currentUserName().c_str()) != 0) { std::fprintf(stderr, "Atlas MFA: --user is not the signed-in user\n"); return 1; }
      } else { std::fprintf(stderr, "usage: atlas-cli-mfa check|ssh-wrap [--service NAME] [--user NAME] | service | serve\n"); return 64; }
    }
    int rc = askService(service);
    if (rc != 0) return rc;
    return mode == L"ssh-wrap" ? runUserCommand() : 0;
  }
  std::fprintf(stderr, "usage: atlas-cli-mfa check|ssh-wrap [--service NAME] [--user NAME] | service | serve\n");
  return 64;
}
