#include "sr_router.h"

int ip_dec_ttl(struct sr_instance* sr, uint8_t * ethPacket, unsigned int len, char* interface);

int ip_hdr_check(struct sr_instance* sr, uint8_t * ethPacket, unsigned int len, char* interface);

/*Handle an ip datagram this router has received
 * @param sr the router instance
 * @param eth_frame the eth frame encapsulating the ip datagram
 * @param ip_datagram the ip datagram received
 * @param ip_datagram_len the size of the ip datagram in bytes
 */
void handleIPDatagram(struct sr_instance* sr, uint8_t* eth_frame, uint8_t* ip_datagram, unsigned int ip_datagram_len);

void sendIPDatagram(struct sr_instance* sr, uint32_t next_hop_ip, char* interface, uint8_t* ip_datagram, unsigned int len);
