// atlas-sync.exe: refresh the cached policy and offline bundle, upload queued offline events.
// Exit codes: 0 ok / nothing to do, 1 server unreachable, 2 broken install, 3 device revoked, 4 server rejected.
#include "agent.hpp"

#include <cstdio>

int wmain() {
  std::shared_ptr<win::Agent> a;
  std::string why;
  switch (win::loadAgent(a, why)) {
    case win::AgentState::Passthrough: std::printf("atlas-sync: nothing to do (%s)\n", why.c_str()); return 0;
    case win::AgentState::Broken: std::fprintf(stderr, "atlas-sync: %s\n", why.c_str()); return 2;
    case win::AgentState::Ready: break;
  }
  std::lock_guard<std::mutex> g(a->mu);
  switch (a->sync->run()) {
    case atlas::SyncOutcome::Ok: std::printf("atlas-sync: ok\n"); return 0;
    case atlas::SyncOutcome::Unreachable: std::fprintf(stderr, "atlas-sync: server unreachable\n"); return 1;
    case atlas::SyncOutcome::Revoked: std::fprintf(stderr, "atlas-sync: this workstation has been revoked\n"); return 3;
    case atlas::SyncOutcome::Rejected: std::fprintf(stderr, "atlas-sync: server rejected the request\n"); return 4;
  }
  return 4;
}
