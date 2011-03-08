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

/*represents an entry in the arp table.
 * The arp table is in the form of a linked list.*/
struct ip_eth_arp_tbl_entry{
	uint32_t ip;
	unsigned char addr[6];
	time_t last_modified;
	struct ip_eth_arp_tbl_entry* next;
};

void handleArpPacket(struct sr_instance* sr, uint8_t * ethPacket, struct sr_if* iface);
