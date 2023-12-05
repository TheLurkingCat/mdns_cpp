#pragma once
#include <cstdint>
#include <functional>
#include <string>

#include "mdns_cpp/defs.hpp"

struct sockaddr;

namespace mdns_cpp {

class mDNS {
 public:
  mDNS();
  ~mDNS();

  void executeQuery(const std::string &service, mdns_record_type qtype, void *userdata);
  void executeDiscovery();

 private:
  int openClientSockets(int *sockets, int max_sockets, int port);

  bool has_ipv4_{false};
  bool has_ipv6_{false};

  uint32_t service_address_ipv4_{0};
  uint8_t service_address_ipv6_[16]{0};
};

}  // namespace mdns_cpp
