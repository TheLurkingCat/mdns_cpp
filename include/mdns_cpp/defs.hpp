#pragma once

struct mdnsRecord {
  char ip[64];
  int port;
};

#ifdef __cplusplus
extern "C" {
#endif

enum mdns_record_type {
  MDNS_RECORDTYPE_IGNORE = 0,
  // Address
  MDNS_RECORDTYPE_A = 1,
  // Domain Name pointer
  MDNS_RECORDTYPE_PTR = 12,
  // Arbitrary text string
  MDNS_RECORDTYPE_TXT = 16,
  // IP6 Address [Thomson]
  MDNS_RECORDTYPE_AAAA = 28,
  // Server Selection [RFC2782]
  MDNS_RECORDTYPE_SRV = 33
};

#ifdef __cplusplus
}
#endif
