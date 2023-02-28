// Solution for: tcpChecksum() function with example usage.  
// File:        tcp-checksum.c
// Author:      Jakub Kuzník

#ifndef INJECT_H 
#define INJECT_H

// normal libraries 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

// network libraries
#include <arpa/inet.h>
#include <netinet/if_ether.h> //ethernet and arp frame 
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <pcap/pcap.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <zlib.h>


#define PH_SIZE 12


struct pseudoHeader {
  uint32_t srcIp;
  uint32_t dstIp;
  uint8_t zero; 
  uint8_t ptcl;
  uint16_t tcpLen; 
};
typedef struct pseudoHeader pseudoHeader;


uint16_t tcpChecksum(uint8_t * data);



#endif 
