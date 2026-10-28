// Windows only. The command-line MFA pipe: the service learns the caller from the pipe, lines are bounded, remote/garbage input ends the session.
#include <gtest/gtest.h>

#include <thread>

#include "cli_pipe.hpp"
#include "winutil.hpp"

namespace {
std::wstring pipeName() { return L"\\\\.\\pipe\\AtlasCliMfaTest-" + std::to_wstring(GetCurrentProcessId()); }

struct Server {
  HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  std::string seenUser, seenDomain, seenMachine;
  std::thread th;
  Server() {
    th = std::thread([this] {
      win::servePipe(pipeName(), [this](const atlas::CliSession::Who& w) {
        seenUser = w.user; seenDomain = w.domain; seenMachine = w.machine;
        return [](const std::string& line, const atlas::CliSession::Say& say) {
          if (line == "PING") { say("PONG"); return true; }
          say("BYE");
          return false;
        };
      }, stop);
    });
    Sleep(300);  // the first pipe instance exists once servePipe is waiting for a client
  }
  ~Server() { SetEvent(stop); th.join(); CloseHandle(stop); }
};
}  // namespace

TEST(CliPipe, ServiceIdentifiesTheCallerFromThePipeAndAnswersLines) {
  Server s;
  std::string err;
  HANDLE h = win::connectPipe(pipeName(), 3000, err);
  ASSERT_TRUE(h) << err;
  win::PipeLine line(h);
  ASSERT_TRUE(line.writeLine("PING"));
  std::string r;
  ASSERT_TRUE(line.readLine(r, 5000));
  EXPECT_EQ(r, "PONG");
  EXPECT_EQ(win::toUtf8(win::currentUserName()), s.seenUser);
  EXPECT_FALSE(s.seenMachine.empty());
  ASSERT_TRUE(line.writeLine("QUIT?"));
  ASSERT_TRUE(line.readLine(r, 5000));
  EXPECT_EQ(r, "BYE");
  EXPECT_FALSE(line.readLine(r, 2000));  // the service ended the session
}

TEST(CliPipe, AnOverlongLineEndsTheSessionWithoutAnAnswer) {
  Server s;
  std::string err;
  HANDLE h = win::connectPipe(pipeName(), 3000, err);
  ASSERT_TRUE(h) << err;
  win::PipeLine line(h);
  std::string big(600, 'A');
  line.writeLine(big);
  std::string r;
  EXPECT_FALSE(line.readLine(r, 3000));
}

TEST(CliPipe, MissingServiceIsReportedAsNotRunning) {
  std::string err;
  EXPECT_FALSE(win::connectPipe(L"\\\\.\\pipe\\AtlasCliMfaDoesNotExist", 100, err));
  EXPECT_NE(err.find("not running"), std::string::npos);
}
