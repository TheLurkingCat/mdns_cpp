#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <iostream>
#include <thread>

#include "mdns_cpp/mdns.hpp"

void onInterruptHandler(int s) {
  std::cout << "Caught signal: " << s << std::endl;
  exit(0);
}

int main() {
  signal(SIGINT, onInterruptHandler);

  mdns_cpp::mDNS service;

  service.setServiceHostname("AirForce1");

  service.startService();

  while (1) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  return 0;
}