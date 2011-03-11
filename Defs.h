/*
 * Defs.h
 *
 *  Created on: 2011-03-07
 *      Author: holman
 */

#define SUCCESS 1
#define ERROR 0
#define TRUE 1
#define FALSE 0

#define ARP_REPLY 2

#define ICMP_ERROR_SIZE 16 //icmp packet size excluding ip header
#define ICMP_START_ERROR 8 //the position where to put IP datagram data
#define ICMP_NUM_IP_BYTES 8 //the number of IP bytes to includes in the icmp data
#define ICMP_REQUEST 8
#define ICMP_REPLY 0
#define ICMP_DEST_UNREACHABLE 3
#define ICMP_HOST_UNREACHABLE 1
#define ICMP_PORT_UNREACHABLE 3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_TIMEOUT 0
#define ICMP_TTL 64

#define IP_ICMP 1
#define IP_TCP 6
#define IP_UDP 17
