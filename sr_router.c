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
#include "icmp.h"
#include "test.h"

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "Ethernet.h"
#include "test.h"

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

    sr->datagram_buff_list = NULL;
    sr->num_datagrams_buffed = 0;
    sr->num_of_datagram_buffers = 0;

    sr->num_arp_entries = 0;

    sr->num_arp_request_trackers = 0;

} /* -- sr_init -- */


void initInterfaces(struct sr_instance* sr){
	assert(sr);

	struct sr_if* iface = sr->if_list;
	while(iface){
		iface->ip_eth_arp_tbl = NULL;
	   	iface->arp_request_tracker_list = NULL;
	   	iface->sr = sr;
	   	iface = iface->next;
	}

	testSendIcmpMsg(sr);
}


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
    handleEthFrame(sr, packet, len, interface);

		//testmethod(sr, packet, len, interface); //for debug, learning purposes
}
