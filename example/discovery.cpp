#include <iostream>

#include "mdns_cpp/mdns.hpp"

int main() {
  mdns_cpp::mDNS mdns;
  mdnsRecord result;
  mdns.executeQuery("dps._http._tcp.local.", MDNS_RECORDTYPE_SRV, &result);
  std::cout << result.ip << ":" << result.port << std::endl;
  return 0;
}
