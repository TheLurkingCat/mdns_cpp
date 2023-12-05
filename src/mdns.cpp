#include "mdns_cpp/mdns.hpp"

#include <iostream>
#include <memory>
#include <vector>

#include "mdns.h"
#include "mdns_cpp/utils.hpp"

#ifdef _WIN32
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#endif
#include <string.h>

namespace mdns_cpp {

int mDNS::openClientSockets(int *sockets, int max_sockets, int port) {
  // When sending, each socket can only send to one network interface
  // Thus we need to open one socket for each interface and address family
  int num_sockets = 0;

#ifdef _WIN32

  IP_ADAPTER_ADDRESSES *adapter_address = nullptr;
  ULONG address_size = 8000;
  unsigned int ret{};
  unsigned int num_retries = 4;
  do {
    adapter_address = (IP_ADAPTER_ADDRESSES *)malloc(address_size);
    ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0, adapter_address,
                               &address_size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
      free(adapter_address);
      adapter_address = 0;
    } else {
      break;
    }
  } while (num_retries-- > 0);

  if (!adapter_address || (ret != NO_ERROR)) {
    free(adapter_address);
    return num_sockets;
  }

  int first_ipv4 = 1;
  int first_ipv6 = 1;
  for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter; adapter = adapter->Next) {
    if (adapter->TunnelType == TUNNEL_TYPE_TEREDO) {
      continue;
    }
    if (adapter->OperStatus != IfOperStatusUp) {
      continue;
    }

    for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
      if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
        struct sockaddr_in *saddr = (struct sockaddr_in *)unicast->Address.lpSockaddr;
        if ((saddr->sin_addr.S_un.S_un_b.s_b1 != 127) || (saddr->sin_addr.S_un.S_un_b.s_b2 != 0) ||
            (saddr->sin_addr.S_un.S_un_b.s_b3 != 0) || (saddr->sin_addr.S_un.S_un_b.s_b4 != 1)) {
          if (first_ipv4) {
            service_address_ipv4_ = saddr->sin_addr.S_un.S_addr;
            first_ipv4 = 0;
          }
          has_ipv4_ = 1;
          if (num_sockets < max_sockets) {
            saddr->sin_port = htons((unsigned short)port);
            int sock = mdns_socket_open_ipv4(saddr);
            if (sock >= 0) sockets[num_sockets++] = sock;
          }
        }
      } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)unicast->Address.lpSockaddr;
        static constexpr unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        static constexpr unsigned char localhost_mapped[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
        if ((unicast->DadState == NldsPreferred) && memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
            memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
          if (first_ipv6) {
            memcpy(service_address_ipv6_, &saddr->sin6_addr, 16);
            first_ipv6 = 0;
          }
          has_ipv6_ = 1;
          if (num_sockets < max_sockets) {
            saddr->sin6_port = htons((unsigned short)port);
            int sock = mdns_socket_open_ipv6(saddr);
            if (sock >= 0) sockets[num_sockets++] = sock;
          }
        }
      }
    }
  }

  free(adapter_address);

#else

  struct ifaddrs *ifaddr = nullptr;
  struct ifaddrs *ifa = nullptr;

  if (getifaddrs(&ifaddr) < 0) {
    std::cerr << "Unable to get interface addresses\n";
  }

  int first_ipv4 = 1;
  int first_ipv6 = 1;
  for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr) {
      continue;
    }

    if (ifa->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in *saddr = (struct sockaddr_in *)ifa->ifa_addr;
      if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        if (first_ipv4) {
          service_address_ipv4_ = saddr->sin_addr.s_addr;
          first_ipv4 = 0;
        }
        has_ipv4_ = 1;
        if (num_sockets < max_sockets) {
          saddr->sin_port = htons(port);
          int sock = mdns_socket_open_ipv4(saddr);
          if (sock >= 0) sockets[num_sockets++] = sock;
        }
      }
    } else if (ifa->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)ifa->ifa_addr;
      static constexpr unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
      static constexpr unsigned char localhost_mapped[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
      if (memcmp(saddr->sin6_addr.s6_addr, localhost, 16) && memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
        if (first_ipv6) {
          memcpy(service_address_ipv6_, &saddr->sin6_addr, 16);
          first_ipv6 = 0;
        }
        has_ipv6_ = 1;
        if (num_sockets < max_sockets) {
          saddr->sin6_port = htons(port);
          int sock = mdns_socket_open_ipv6(saddr);
          if (sock >= 0) sockets[num_sockets++] = sock;
        }
      }
    }
  }

  freeifaddrs(ifaddr);

#endif

  return num_sockets;
}

int query_callback(int, const struct sockaddr *, size_t, mdns_entry_type_t, uint16_t, uint16_t rtype, uint16_t,
                   uint32_t, const void *data, size_t size, size_t, size_t, size_t record_offset, size_t record_length,
                   void *user_data) {
  if (user_data == nullptr) return 0;

  mdnsRecord &output = *reinterpret_cast<mdnsRecord *>(user_data);

  static char namebuffer[256]{};

  if (rtype == MDNS_RECORDTYPE_SRV) {
    mdns_record_srv_t srv =
        mdns_record_parse_srv(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
    output.port = srv.port;
  } else if (rtype == MDNS_RECORDTYPE_A) {
    struct sockaddr_in addr;
    mdns_record_parse_a(data, size, record_offset, record_length, &addr);
    const auto addrstr = ipv4AddressToString(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
    strcpy(output.ip, addrstr.c_str());
  } else if (rtype == MDNS_RECORDTYPE_AAAA) {
    struct sockaddr_in6 addr;
    mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
    const auto addrstr = ipv6AddressToString(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
    strcpy(output.ip, addrstr.c_str());
  }
  return 0;
}

mDNS::mDNS() {
#ifdef _WIN32
  WSADATA wsaData;
  // Initialize Winsock
  const int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult != 0) {
    std::cerr << "WSAStartup failed: " << iResult << "\n";
  }
#endif
}

mDNS::~mDNS() {
#ifdef _WIN32
  WSACleanup();
#endif
}

void mDNS::executeQuery(const std::string &service, mdns_record_type qtype, void *userdata) {
  int sockets[32];
  int query_id[32];
  int num_sockets = openClientSockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);

  if (num_sockets <= 0) {
    const auto msg = "Failed to open any client sockets";
    std::cerr << msg << "\n";
    throw std::runtime_error(msg);
  }

  size_t capacity = 2048;
  std::vector<char> buffer(capacity);
  size_t records;

  std::cout << "Sending mDNS query: " << service << "\n";
  for (int isock = 0; isock < num_sockets; ++isock) {
    query_id[isock] =
        mdns_query_send(sockets[isock], qtype, service.data(), strlen(service.data()), buffer.data(), capacity, 0);
    if (query_id[isock] < 0) {
      std::cerr << "Failed to send mDNS query: " << strerror(errno) << "\n";
    }
  }

  // This is a simple implementation that loops for 5 seconds or as long as we
  // get replies
  int res{};
  std::cout << "Reading mDNS query replies\n";
  do {
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    int nfds = 0;
    fd_set readfs;
    FD_ZERO(&readfs);
    for (int isock = 0; isock < num_sockets; ++isock) {
      if (sockets[isock] >= nfds) nfds = sockets[isock] + 1;
      FD_SET(sockets[isock], &readfs);
    }

    records = 0;
    res = select(nfds, &readfs, 0, 0, &timeout);
    if (res > 0) {
      for (int isock = 0; isock < num_sockets; ++isock) {
        if (FD_ISSET(sockets[isock], &readfs)) {
          records +=
              mdns_query_recv(sockets[isock], buffer.data(), capacity, query_callback, userdata, query_id[isock]);
        }
        FD_SET(sockets[isock], &readfs);
      }
    }
  } while (res > 0);

  for (int isock = 0; isock < num_sockets; ++isock) {
    mdns_socket_close(sockets[isock]);
  }
}

void mDNS::executeDiscovery() {
  int sockets[32];
  int num_sockets = openClientSockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
  if (num_sockets <= 0) {
    const auto msg = "Failed to open any client sockets";
    std::cerr << msg << "\n";
    throw std::runtime_error(msg);
  }

  std::cout << "Sending DNS-SD discovery\n";
  for (int isock = 0; isock < num_sockets; ++isock) {
    if (mdns_discovery_send(sockets[isock])) {
      std::cerr << "Failed to send DNS-DS discovery: " << strerror(errno) << " \n";
    }
  }

  size_t capacity = 2048;
  std::vector<char> buffer(capacity);
  void *user_data = 0;
  size_t records;

  // This is a simple implementation that loops for 5 seconds or as long as we
  // get replies
  int res;
  std::cout << "Reading DNS-SD replies\n";
  do {
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    int nfds = 0;
    fd_set readfs;
    FD_ZERO(&readfs);
    for (int isock = 0; isock < num_sockets; ++isock) {
      if (sockets[isock] >= nfds) nfds = sockets[isock] + 1;
      FD_SET(sockets[isock], &readfs);
    }

    records = 0;
    res = select(nfds, &readfs, 0, 0, &timeout);
    if (res > 0) {
      for (int isock = 0; isock < num_sockets; ++isock) {
        if (FD_ISSET(sockets[isock], &readfs)) {
          records += mdns_discovery_recv(sockets[isock], buffer.data(), capacity, query_callback, user_data);
        }
      }
    }
  } while (res > 0);

  for (int isock = 0; isock < num_sockets; ++isock) {
    mdns_socket_close(sockets[isock]);
  }
}

}  // namespace mdns_cpp
