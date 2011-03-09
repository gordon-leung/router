#include "ip.h"

//TODO:These functions need to be tested. Especially for ntohs, htons.

//If TTL <= 1, then generate ICMP timeout packet
//Else Decrement TTL, recompute checksum, and send
int ip_dec_ttl(struct sr_instance* sr, uint8_t * ethPacket, unsigned int len, char* interface){
	struct ip* ip_hdr = NULL;
	ip_hdr = (struct ip*)(ethPacket + sizeof(struct sr_ethernet_hdr));//cast ip header
	if(ip_hdr->ip_ttl <= 1){
		//send icmp
		return -1;
	}
	else{
		ip_hdr->ip_ttl--;
		ip_hdr->ip_sum = 0; //clear checksum
		ip_hdr->ip_sum = csum((uint16_t*)ip_hdr, 4*(ip_hdr->ip_hl)); //recompute

		//send it out
	}
	return 0;
}

//Check if IP datagram is valid, else drop it.
//Return -1 on fail
//Return 1 on success
int ip_hdr_check(struct sr_instance* sr, uint8_t * ethPacket, unsigned int len, char* interface){

	struct ip* ip_hdr = NULL;
	ip_hdr = (struct ip*)(ethPacket + sizeof(struct sr_ethernet_hdr));//cast ip header
	if(ntohs(ip_hdr->ip_len) < 20){//datagram too short.
		return -1;
	}
	if(ntohs(ip_hdr->ip_v) != 4){//not IP_V4
		return -1;
	}
	if(ntohs(ip_hdr->ip_hl) > 5){//datagram has options set, drop it
		return -1;
	}
	uint16_t checksum = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0; //clear checksum
	//recompute and check
	if(checksum != csum((uint16_t*)ip_hdr, 4*(ip_hdr->ip_hl))){
		return -1;
	}
	
	return 1;
}
