#include "sr_router.h"

int ip_dec_ttl(struct sr_instance* sr, uint8_t * ethPacket, unsigned int len, char* interface);

int ip_hdr_check(struct sr_instance* sr, uint8_t * ethPacket, unsigned int len, char* interface);

/*Handle an ip datagram this router has received
 * @param sr the router instance
 * @param ip_datagram the ip datagram received
 * @param len the size of the ip datagram in bytes
 */
void handleIPDatagram(struct sr_instance* sr, uint8_t* ip_datagram, unsigned int len, char* interface);//FIXME: passing in interface is a hack, remove it later
