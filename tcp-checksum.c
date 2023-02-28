// Solution for: tcpChecksum() function with example usage.  
// File:        tcp-checksum.c
// Author:      Jakub Kuzník

#include "tcp-checksum.h"

/*
  Pseudo tcp header.  
  c0 a8 58 fa 
  c0 a8 58 fc 
  00 06 00 20
  Tcp header. 
  d3 3a 01 f6
  05 04 35 6c 
  14 5c 35 00
  00 18 01 f6 
  00 00 00 00 
  TCP Payload 
  c3 50 00 00
  00 06 01 05 
  00 03 ff 00 

  0x5e26 should be the result 🥹
*/

int main(void){

  // pseudo header
  // RFC says that:
  //  tcpLen: TcpHeaderLen + TcpPayload in Bytes 
  //  ptcl: 6 for TCP 
  /***************************/
  /*      source address     */
  /***************************/
  /*       dest address      */
  /***************************/
  /* zero | PTCL |  tcpLen   */
  /***************************/

  pseudoHeader ph; 
  ph.srcIp  = htonl(0xc0a858fa);
  ph.dstIp  = htonl(0xc0a858fc);
  ph.zero   = 0x00;
  ph.ptcl   = TCP;
  ph.tcpLen = htons(0x20); // 32 bytes 

  struct tcphdr tcpHeader;
  tcpHeader.source = htons(0xd33a);      // Source port: 54298 (0xd33a)
  tcpHeader.dest = htons(0x01f6);        // Destination port: 502 (0x01f6)
  tcpHeader.seq = htonl(0x0504356c);     // Sequence number: 0x0504356c
  tcpHeader.ack_seq = htonl(0x145c3500); // Acknowledgment number: 0x145c3500
  tcpHeader.doff = htons(0x05);          // Data offset (header length): 20 bytes (0x05)
  tcpHeader.th_flags = 0x18;             // Flags: ACK PSH
  tcpHeader.window = htons(0x01f6);      // Window size: 0x01f6
  // ! important you have to set tcp checksum to 0 always 
  tcpHeader.check = 0x0000;              // Checksum: 0x0000 (set to 0 initially)
  tcpHeader.urg_ptr = 0x0000;            // Urgent pointer: 0x0000

  // data will be interpreted as 16 bit word no matter what 
  unsigned char data[] = {
    0xc3, 0x50, 0x00, 0x00,
    0x00, 0x06, 0x01, 0x05,
    0x00, 0x03, 0xff, 0x00
  };

  unsigned char *rawData = (char*) malloc(sizeof(pseudoHeader) + sizeof(struct tcphdr) + sizeof(data));
  memcpy(rawData, &ph, sizeof(pseudoHeader));
  memcpy(rawData+ sizeof(pseudoHeader), &tcpHeader, sizeof(struct tcphdr));
  memcpy(rawData + sizeof(pseudoHeader) + sizeof(struct tcphdr), data, sizeof(data)); 

  for (int i = 0; i < sizeof(ph) + sizeof(struct tcphdr) + sizeof(data); i++){
    printf("%02x ",rawData[i]);
  }

  return 0;
}

/**
 * @brief count tcp checksum
 * 
 * @param data input data ph contatenated with tcp header and payload 
 * @param len data lenght 
 * @return uint16_t checksum 
 */
uint16_t tcpChecksum(uint8_t * data, int len){
  return 0;  
}