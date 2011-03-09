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

/*represents an entry in the arp table.
 * The arp table is in the form of a linked list.*/
struct ip_eth_arp_tbl_entry{
	uint32_t ip;
	unsigned char addr[6];
	time_t last_modified;
	struct ip_eth_arp_tbl_entry* previous;
	struct ip_eth_arp_tbl_entry* next;
};

/*Handle a arp packet received from the specified interface.
 * @param sr the router instance
 * @param ethPacket the eth frame received encapsulating the
 * 		arp header
 * @param iface the interface where the fram is received from
 */
void handleArpPacket(struct sr_instance* sr, uint8_t * ethPacket, struct sr_if* iface);

/*Resulve the mac address the target interface's mac address.
 * A arp request may be sent if the corresponding arp table
 * entry does not already exist or has expired.
 * given target interface's ip address
 * @param sr the simple router instance
 * @param ip the target interface's ip
 * @param iface the interface on this router
 * 		where the arp resolution is associated to
 * 		and where a arp request is to be sent
 * 		from if one is needed.
 * @return the pointer to the mac address resolved or NULL
 * 		if the resolution is not done an an arp request has
 * 		been sent.
 */
uint8_t* resolve(struct sr_instance* sr, const uint32_t ip, struct sr_if* iface);
