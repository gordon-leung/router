/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stddef.h>

#include "sr_router.h"
#include "arp.h"
#include "icmp.h"
#include "test.h"

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "Ethernet.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    struct sr_if* iface = sr->if_list;
    while(iface){
    	iface->ip_eth_arp_tbl = NULL;
    	iface = iface->next;
    }

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    printf("*** -> Received packet of length %d\n",len);
    handleEthPacket(sr, packet, len, interface);


//		testmethod(sr, packet, len, interface); //for debug, learning purposes
}

/*--------------------------------------------------------------------- 
 * Method: ethernet_swap_src_dest(...)
 *
 * Puts the source mac addr into the destination mac addr
 * And puts the interface mac addr into the source mac addr
 *---------------------------------------------------------------------*/
void ethernet_swap_src_dest(struct sr_instance* sr, uint8_t * packet, char* interface){
		struct sr_ethernet_hdr* e_hdr = NULL;//init
		struct sr_if* iface = sr_get_interface(sr, interface); //packet is from which interface?
		e_hdr = (struct sr_ethernet_hdr*)packet;//cast ethernet header
		
		for(int i=0; i<ETHER_ADDR_LEN; i++){
			e_hdr->ether_dhost[i] = e_hdr->ether_shost[i];
			e_hdr->ether_shost[i] = iface->addr[i];
		}
}
