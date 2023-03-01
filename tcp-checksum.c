// Solution for: tcpChecksum() function with example usage.  
// File:        tcp-checksum.c
// Author:      Jakub Kuzník

#include "tcp-checksum.h"

/* IT IS IMPORTANT THAT EVERYTHING IS IN NETWORK BYTE ORDER 
   ESPECIALLY THE FLAGS AR TRICKY (SAME AS WIRESHARK BYTE ORDER)*/


/* example packet: 
    
    00 00 00 01 00 06 8c 04 ba 08 73 03 00 00 08 00
    45 00 00 34 92 87 40 00 40 06 74 f5 c0 a8 58 fa 
    c0 a8 58 fc d3 3a 01 f6 05 04 35 6c 14 5c 35 00 
    50 18 01 f6 b8 18 00 00 c3 50 00 00 00 06 01 05 
    00 03 ff 00

Internet Protocol Version 4, Src: 192.168.88.250, Dst: 192.168.88.252
    0100 .... = Version: 4
    .... 0101 = Header Length: 20 bytes (5)
    Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
    Total Length: 52
    Identification: 0x9287 (37511)
    Flags: 0x40, Don't fragment
    ...0 0000 0000 0000 = Fragment Offset: 0
    Time to Live: 64
    Protocol: TCP (6)
    Header Checksum: 0x74f5 [validation disabled]
    [Header checksum status: Unverified]
    Source Address: 192.168.88.250
    Destination Address: 192.168.88.252
Transmission Control Protocol, Src Port: 54074, Dst Port: 502, Seq: 385, Ack: 385, Len: 12
    Source Port: 54074
    Destination Port: 502
    [Stream index: 1]
    [Conversation completeness: Incomplete (12)]
    [TCP Segment Len: 12]
    Sequence Number: 385    (relative sequence number)
    Sequence Number (raw): 84161900
    [Next Sequence Number: 397    (relative sequence number)]
    Acknowledgment Number: 385    (relative ack number)
    Acknowledgment number (raw): 341587200
    0101 .... = Header Length: 20 bytes (5)
    Flags: 0x018 (PSH, ACK)
        000. .... .... = Reserved: Not set
        ...0 .... .... = Nonce: Not set
        .... 0... .... = Congestion Window Reduced (CWR): Not set
        .... .0.. .... = ECN-Echo: Not set
        .... ..0. .... = Urgent: Not set
        .... ...1 .... = Acknowledgment: Set
        .... .... 1... = Push: Set
        .... .... .0.. = Reset: Not set
        .... .... ..0. = Syn: Not set
        .... .... ...0 = Fin: Not set
        [TCP Flags: ·······AP···]
    Window: 502
    [Calculated window size: 502]
    [Window size scaling factor: -1 (unknown)]
    Checksum: 0xb818 incorrect, should be 0x5e26(maybe caused by "TCP checksum offload"?)
    [Checksum Status: Bad]
    [Calculated Checksum: 0x5e26]
    Urgent Pointer: 0
    [Timestamps]
    [SEQ/ACK analysis]
    TCP payload (12 bytes)
    [PDU Size: 12]
Modbus/TCP
    Transaction Identifier: 50000
    Protocol Identifier: 0
    Length: 6
    Unit Identifier: 1
Modbus
    .000 0101 = Function Code: Write Single Coil (5)
    Reference Number: 3
    Data: ff00
    Padding: 0x00
*/


/* information from packed that is used for calculation 
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

  printf("packet in network byte order (big endian):\n");
  printf(" 00 00 00 01 00 06 8c 04 ba 08 73 03 00 00 08 00\n \
45 00 00 34 92 87 40 00 40 06 74 f5 c0 a8 58 fa\n \
c0 a8 58 fc d3 3a 01 f6 05 04 35 6c 14 5c 35 00\n \
50 18 01 f6 b8 18 00 00 c3 50 00 00 00 06 01 05\n \ 
00 03 ff 00\n");

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
  
  // tcp header 
  struct tcphdr tcpHeader;
  tcpHeader.source = htons(0xd33a);      // Source port: 54298 (0xd33a)
  tcpHeader.dest = htons(0x01f6);        // Destination port: 502 (0x01f6)
  tcpHeader.seq = htonl(0x0504356c);     // Sequence number: 0x0504356c
  tcpHeader.ack_seq = htonl(0x145c3500); // Acknowledgment number: 0x145c3500

  // Tricky is to set the flags correct way 
  char *pt = &tcpHeader.ack_seq;
  pt = pt + 4;
  char a[2];
  a[0] = 0x50;
  a[1] = 0x18;
  memcpy(pt, &a, 2);

  tcpHeader.window = htons(0x01f6);      // Window size: 0x01f6
  // ! important you have to set tcp checksum to 0 always 
  tcpHeader.check = 0x0000;              // Checksum: 0x0000 (set to 0 initially)
  tcpHeader.urg_ptr = 0x0000;            // Urgent pointer: 0x0000

  // TCP payload. It will be interpreted as 16 bit word no matter what 
  unsigned char data[] = {
    0xc3, 0x50, 0x00, 0x00,
    0x00, 0x06, 0x01, 0x05,
    0x00, 0x03, 0xff, 0x00
  };

  unsigned char *rawData = (char*) malloc(sizeof(pseudoHeader) + sizeof(struct tcphdr) + sizeof(data));
  memcpy(rawData, &ph, sizeof(pseudoHeader));
  memcpy(rawData+ sizeof(pseudoHeader), &tcpHeader, sizeof(struct tcphdr));
  memcpy(rawData + sizeof(pseudoHeader) + sizeof(struct tcphdr), data, sizeof(data)); 

  int len = sizeof(ph) + sizeof(struct tcphdr) + sizeof(data);
  printf("PseudoHeader + tcpHeader + tcpPayload:\n");
  for (int i = 0; i < len; i++){
    printf("%02x ",rawData[i]);
  }

  uint16_t tcpCh = tcpChecksum(rawData, len);
  printf("\nChecksum: %04x\n",tcpCh);


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
  uint16_t *buf = (uint16_t*)data;
  int bufLen = len / 2;

  // Calculate the TCP checksum
  uint32_t sum = 0;
  for (int i = 0; i < bufLen; i++) {
    sum += ntohs(buf[i]);
  }

  // Add in any odd byte
  if (len % 2) {
    sum += ((uint16_t)data[len-1]) << 8;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  // Return the 1's complement of the result
  return (uint16_t)(~sum);

}