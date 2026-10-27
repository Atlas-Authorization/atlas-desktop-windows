// ISecretStore backed by DPAPI (machine scope) files in %ProgramData%\Atlas\secrets, ACL'd to SYSTEM + Administrators.
#pragma once
#include "atlas/base.hpp"

#include <string>

namespace win {

class DpapiStore : public atlas::ISecretStore {
 public:
  DpapiStore();
  std::optional<atlas::Bytes> get(const std::string& name) override;
  bool put(const std::string& name, const atlas::Bytes& value) override;
  void remove(const std::string& name) override;

 private:
  std::wstring pathFor(const std::string& name) const;
  std::wstring dir_;
};

}  // namespace win
