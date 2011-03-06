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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

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

    /* Add initialization code here! */

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
		
		struct sr_ethernet_hdr* e_hdr = 0;
    struct sr_arphdr*       a_hdr = 0;
		a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
		struct sr_if* iface = sr_get_interface(sr, interface);

    printf("*** -> Received packet of length %d from interface %u \n",len, iface->ip);
		e_hdr = (struct sr_ethernet_hdr*)packet;
		printf("%d\n",ntohs(e_hdr->ether_type));
		printf("%d\n",(ETHERTYPE_ARP));
		printf("%d\n",a_hdr->ar_hrd);

		for(int i=0; i<6; i++){
			printf("%d",e_hdr->ether_dhost[i]);
			printf(" ");
		}
		printf("\n");

		for(int i=0; i<6; i++){
			printf("%d",e_hdr->ether_shost[i]);
			printf(" ");
		}
		printf("\n");

		for(int i=0; i<6; i++){
			printf("%d",a_hdr->ar_sha[i]);
			printf(" ");
		}
		printf("\n");
}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
