#include "arp.h"

/*--------------------------------------------------------------------- 
 * Method: arp_reply(...)
 * Return: 0 on success
 *
 * Replies to an ARP Request
 *---------------------------------------------------------------------*/

int arp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
		
    struct sr_arphdr*       a_hdr = 0;//init
		struct sr_if* iface = sr_get_interface(sr, interface); //packet is from which interface?

//BEGIN ARP REPLY MODIFICATION

		//ETHERNET HEADER CHANGES
		ethernet_swap_src_dest(sr, packet, interface);
		
		//ARP HEADER CHANGES
		a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr)); //cast arp header
		//opcode = 2 for ARP REPLY
		a_hdr->ar_op = htons(2);
		//target hardware addr = source hardware addr
		//at same time change sender hardware addr = interface mac addr
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
