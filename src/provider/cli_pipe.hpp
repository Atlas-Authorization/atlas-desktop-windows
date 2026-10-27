// The named pipe between the unprivileged command-line client and the service that holds the device keys.
// The service learns WHO is asking from the pipe (ImpersonateNamedPipeClient), never from what the client says.
#pragma once
#include "atlas/cli.hpp"

#include <windows.h>

#include <functional>
#include <string>

namespace win {

constexpr const wchar_t* kCliPipe = L"\\\\.\\pipe\\AtlasCliMfa";

// Newline-delimited lines over an overlapped pipe handle, with timeouts. Lines longer than 255 bytes close the stream.
class PipeLine {
 public:
  explicit PipeLine(HANDLE h) : h_(h) {}
  ~PipeLine();
  PipeLine(const PipeLine&) = delete;
  PipeLine& operator=(const PipeLine&) = delete;
  bool readLine(std::string& out, DWORD timeoutMs);
  bool writeLine(const std::string& line);
  HANDLE handle() const { return h_; }

 private:
  HANDLE h_;
  std::string buf_;
};

using LineHandler = std::function<bool(const std::string&, const atlas::CliSession::Say&)>;  // false = session over
using HandlerFactory = std::function<LineHandler(const atlas::CliSession::Who&)>;

// Serves until `stop` is signalled. At most 16 clients at once. Remote clients are rejected by the pipe itself.
void servePipe(const std::wstring& name, const HandlerFactory& factory, HANDLE stop);

// Connects as a client (identification impersonation level only). Null handle on failure; sets `err`.
HANDLE connectPipe(const std::wstring& name, DWORD waitMs, std::string& err);

}  // namespace win
