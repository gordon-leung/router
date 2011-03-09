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
		printf("type of service %x\n",ip_hdr->ip_tos);//?
		printf("len %d\n",ip_hdr->ip_len);//recompute length?
		printf("identification %x\n",ip_hdr->ip_id);//?
		//set time-to-live
		ip_hdr->ip_ttl = ICMP_TTL;
		printf("time to live %x\n",ip_hdr->ip_ttl);
		printf("checksum %x\n",ip_hdr->ip_sum);//need to recompute
		//swap source addr with destination addr
		temp_addr = ip_hdr->ip_src.s_addr;
		ip_hdr->ip_src.s_addr = ip_hdr->ip_dst.s_addr;
		printf("source addr %d\n",ip_hdr->ip_src.s_addr);
		ip_hdr->ip_dst.s_addr = temp_addr;
		printf("destination addr %d\n",ip_hdr->ip_dst.s_addr);
		//ICMP HEADER CHANGES
		//cast icmp header
		icmp_hdr = (struct icmphdr*)(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip));
		//set type = ICMP REPLY
		icmp_hdr->icmp_type = ICMP_REPLY;
		printf("icmp type %d\n", icmp_hdr->icmp_type);
		printf("icmp code %x\n", icmp_hdr->icmp_code);
		printf("icmp checksum %x\n", icmp_hdr->icmp_checksum);
//END ICMP REPLY MODIFICATION

		//send it out
//		return sr_send_packet(sr, packet, len, interface);
		return 0;
}
