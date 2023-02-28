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
  50 18 01 f6 
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

  



  


  return 0;
}

uint16_t tcpChecksum(uint8_t * data){
  return;  
}