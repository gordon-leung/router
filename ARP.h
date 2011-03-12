/*
 * ARP.h
 *
 *  Created on: 2011-03-06
 *      Author: holman
 */

#include <time.h>

#include "sr_protocol.h"
#include "sr_if.h"

#define IP_ADDR_LEN 4
#define ARP_TBL_ENTRY_TTL 15

//the time to wait before the next arp
//request for the same ip can be sent
//again. measure in seconds
#define ARP_REQUEST_WAIT_TIME 0.01

//the max number of arp requests that
//can be sent for the same ip
#define MAX_NUM_ARP_REQUESTS 5

#define ARP_RESOLVE_SUCCESS 0
#define ARP_REQUEST_SENT 1
#define ARP_RESOLVE_FAIL 2

/*represents an entry in the arp table.
 * The arp table is in the form of a linked list.*/
struct ip_eth_arp_tbl_entry{
	uint32_t ip;
	unsigned char mac_addr[ETHER_ADDR_LEN];
	time_t last_modified;
	struct ip_eth_arp_tbl_entry* previous;
	struct ip_eth_arp_tbl_entry* next;
};

/*for a given ip addr whose mac we wish to resolve
 * this struct keeps strack of the time when the
 * last arp request is sent and the number of arp
 * requests sent so far
 */
struct arp_request_tracker{
	uint32_t ip;
	time_t last_arp_request_send_time;
	unsigned short num_arp_request_sent;
	struct arp_request_tracker* previous;
	struct arp_request_tracker* next;
};

/*Handle a arp packet received from the specified interface.
 * @param sr the router instance
 * @param ethPacket the eth frame received encapsulating the
 * 		arp header
 * @param iface the interface where the fram is received from
 */
void handleArpPacket(struct sr_instance* sr, uint8_t * ethPacket, struct sr_if* iface);

/*Resulve the mac address from the target interface's ip address.
 * A arp request may be sent if the corresponding arp table
 * entry does not already exist or has expired.
 * given target interface's ip address
 * @param sr the simple router instance
 * @param ip the target interface's ip
 * @param iface the interface on this router
 * 		where the arp resolution is associated to
 * 		and where a arp request is to be sent
 * 		from if one is needed.
 * @param mac_buff the buffer for storing the mac addr resolved
 * @return 0 if the resolution succeed, 1 if local resolution
 * 	failed but an arp request is sent, 2 if arp resolution failed
 * 	with arp requests
 */
int resolveMAC(struct sr_instance* sr, const uint32_t ip, struct sr_if* iface, uint8_t* mac_buff);
