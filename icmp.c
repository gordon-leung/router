#include "icmp.h"

/*--------------------------------------------------------------------- 
 * Method: icmp_reply(...)
 * Return: 0 on success
 *
 * Replies to an ICMP Request
 *---------------------------------------------------------------------*/
int icmp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
		struct ip*       	ip_hdr = NULL;	//init
		struct icmphdr*		icmp_hdr = NULL;//init
		struct sr_if* iface = sr_get_interface(sr, interface); //packet is from which interface?
		unsigned long temp_addr = 0;
//BEGIN ICMP REPLY MODIFICATION

		//ETHERNET HEADER CHANGES
		ethernet_swap_src_dest(sr, packet, interface);

		//IP HEADER CHANGES
		ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));//cast ip header
		//set time-to-live
		ip_hdr->ip_ttl = ICMP_TTL;
		//swap source addr with destination addr
		temp_addr = ip_hdr->ip_src.s_addr;
		ip_hdr->ip_src.s_addr = ip_hdr->ip_dst.s_addr;
		ip_hdr->ip_dst.s_addr = temp_addr;
		//recompute ip checksum
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = csum((uint16_t*)ip_hdr, 4*(ip_hdr->ip_hl));
		//ICMP HEADER CHANGES
		//cast icmp header
		icmp_hdr = (struct icmphdr*)(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip));
		//set type = ICMP REPLY
		icmp_hdr->icmp_type = ICMP_REPLY;
		//recompute icmp checksum
		icmp_hdr->icmp_checksum = 0;
		icmp_hdr->icmp_checksum = csum((uint16_t*)icmp_hdr,(ntohs((ip_hdr->ip_len)) - 4*(ip_hdr->ip_hl)));
//END ICMP REPLY MODIFICATION

		//send it out
		return sr_send_packet(sr, packet, len, interface);
}
