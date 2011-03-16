#include "sr_router.h"

#define ICMP_HDR_LEN 8 //8 bytes for at least the icmp header
#define MAX_IP_DATA_LEN 8 //corresponds to the first 64 bits of the original ip datagram

#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_CODE_ECHO 0

#define ICMP_TYPE_DESTINATION_UNREACHABLE 3
#define ICMP_CODE_NET_UNREACHABLE 0
#define ICMP_CODE_HOST_UNREACHABLE 1
#define ICMP_CODE_PROTOCOL_UNREACHABLE 2
#define ICMP_CODE_PORT_UNREACHABLE 3

#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_CODE_TTL_EXCEEDED 0

/*For a given ip datagram whose ttl has exceeded, generate an
 * icmp message to be sent back to the sender of the ip datagram
 * @param sr the router instance
 * @param ip_datagram the ip datagram causeing the icmp message to
 * 		me generated
 * @param ip_datagram_len the size of the ip datagram in bytes
 */
void ipDatagramTimeExceeded(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len);

/*For a given ip datagram whose destination can't be reached, generate an
 * icmp message to be sent back to the sender of the ip datagram
 * @param sr the router instance
 * @param ip_datagram the ip datagram causeing the icmp message to
 * 		me generated
 * @param ip_datagram_len the size of the ip datagram in bytes
 */
void destinationUnreachable(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len, unsigned short code);

/*Handle the icmp message destined at this router. (Currently
 * only handle ping request, any other types of icmp message
 * are dropped)
 * @param ip_datagram the ip datagram encapsulating the icmp
 * 		message
 * @param ip_datagram_len the size of the ip datagram in bytes
 */
void handleIcmpMessageReceived(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len);

