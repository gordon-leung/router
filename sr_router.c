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

    printf("*** -> Received packet of length %d\n",len);

		//FIGURE OUT WHAT TO DO WITH INCOMING PACKET
		struct sr_ethernet_hdr* e_hdr = 0;//init
		e_hdr = (struct sr_ethernet_hdr*)packet;//cast ethernet header

		//TODO: make e_hdr->ether_type into case statement?
		//ARP PACKET!
		if((e_hdr->ether_type) == htons(ETHERTYPE_ARP)){
			printf("Got an ARP packet!\n");
			if(arp_reply(sr, packet, len, interface) == 0){
				printf("ARP REPLY sent!\n");
			}
		}

		//testmethod(sr, packet, len, interface);
}
/* end sr_ForwardPacket */
/*--------------------------------------------------------------------- 
 * Method: arp_reply
 * Return: 0 on success
 *---------------------------------------------------------------------*/
int arp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
		
		struct sr_ethernet_hdr* e_hdr = 0;//init
    struct sr_arphdr*       a_hdr = 0;//init
		struct sr_if* iface = sr_get_interface(sr, interface); //packet is from which interface?

//BEGIN ARP REPLY MODIFICATION

		//ETHERNET HEADER CHANGES
		e_hdr = (struct sr_ethernet_hdr*)packet;//cast ethernet header
		//put source mac addr in destination mac addr
		//at same time replace source mac addr with eth0 mac addr
		for(int i=0; i<ETHER_ADDR_LEN; i++){
			e_hdr->ether_dhost[i] = e_hdr->ether_shost[i];
			e_hdr->ether_shost[i] = iface->addr[i];
		}
		
		//ARP HEADER CHANGES
		a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr)); //cast arp header
		//opcode = 2 for ARP REPLY
		a_hdr->ar_op = htons(2);
		//target hardware addr = source hardware addr
		//at same time change sender hardware addr = eth0 mac addr
		for(int i=0; i<ETHER_ADDR_LEN; i++){
			a_hdr->ar_tha[i] = a_hdr->ar_sha[i];
			a_hdr->ar_sha[i] = iface->addr[i];
		}
		//target ip = sending ip
		a_hdr->ar_tip = a_hdr->ar_sip;
		//sending ip addr = eth0 ip addr
		a_hdr->ar_sip = iface->ip;

//END ARP REPLY MODIFICATION

		//send it out
		return sr_send_packet(sr, packet, len, interface);
}

/*--------------------------------------------------------------------- 
 * Method: testmethod for debug and learning purposes
 *
 *---------------------------------------------------------------------*/
void testmethod(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
		
		struct sr_ethernet_hdr* e_hdr = 0;//init
    struct sr_arphdr*       a_hdr = 0;//init

		struct sr_if* iface = sr_get_interface(sr, interface); //packet is from which interface?
		struct sockaddr_in sa;
		sa.sin_addr.s_addr = iface->ip;//assign binary value to s_addr
		char dotted_ip[INET_ADDRSTRLEN]; //should contain dotted-decimal format of interface ip
		inet_ntop(AF_INET, &(sa.sin_addr), dotted_ip, INET_ADDRSTRLEN);
		printf("*** -> Received packet of length %d on interface %s with ip %s\n",len, interface, dotted_ip);

		for(int i=0; i<6; i++){//mac address of interface
			printf("%x ",iface->addr[i]);
		}

		e_hdr = (struct sr_ethernet_hdr*)packet;//cast ethernet header
		printf("Destination mac address: ");
		for(int i=0; i<ETHER_ADDR_LEN; i++){//destination mac address
			printf("%x",e_hdr->ether_dhost[i]);
			printf(" ");
		}
		printf("\n");
		printf("Source mac address: ");
		for(int i=0; i<ETHER_ADDR_LEN; i++){//source mac address
			printf("%x",e_hdr->ether_shost[i]);
			printf(" ");
		}
		printf("\n");

		if((e_hdr->ether_type) == htons(ETHERTYPE_ARP)){
			//it's an arp packet!
			a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr)); //cast arpheader
			printf("ARP sender address: ");
			for(int i=0; i<6; i++){//hardware type
				printf("%x",a_hdr->ar_sha[i]);
				printf(" ");
			}
			printf("\n");
			sa.sin_addr.s_addr = a_hdr->ar_sip;
			inet_ntop(AF_INET, &(sa.sin_addr), dotted_ip, INET_ADDRSTRLEN);
			printf("Sender IP: %d %s\n",a_hdr->ar_sip, dotted_ip);
		}
}
