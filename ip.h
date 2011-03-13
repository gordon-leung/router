#include "sr_router.h"


/*Handle an ip datagram this router has received
 * @param sr the router instance
 * @param eth_frame the eth frame encapsulating the ip datagram
 * @param ip_datagram the ip datagram received
 * @param ip_datagram_len the size of the ip datagram in bytes
 */
void handleIPDatagram(struct sr_instance* sr, uint8_t* eth_frame, uint8_t* ip_datagram, unsigned int ip_datagram_len);

/*Send an ip datagram
 * @param sr the router instance
 * @param next_hop_ip the ip addr of the next hop
 * @param interface the name of the interface on this router
 * 		that is to be used to send out the eth frame containing
 * 		the ip datagram
 * @param eth_frame the eth frame containing the ip datagram. Note
 * 		NULL should be passed in if the ip datagram is not currently
 * 		encapsulated inside an eth frame
 * @ip_datagram_len the size of the ip datagram in bytes
 */
void sendIPDatagram(struct sr_instance* sr, uint32_t next_hop_ip, char* interface, uint8_t* ip_datagram, uint8_t* eth_frame, unsigned int ip_datagram_len);

void sendIcmpMessage(struct sr_instance* sr, uint8_t* icmp_message, unsigned int icmp_msg_len, uint32_t dest_ip, uint32_t src_ip);
