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

void handleIPDatagram(struct sr_instance* sr, uint8_t* ip_datagram, unsigned int len){
	/*TODO: this is the entry point into the ip layer. This method
	 * will be called by the ethernet layer when it received an ip
	 * datagram that is targeted for this router.
	 *
	 * A few things to do here:
	 * 	1. run the ip hdr through the check sum code to make sure
	 * 		the check sum is correct.
	 * 		1.1 if the check sum is not correct, the datagram should
	 * 			not be forwarded and instead the it should be passed
	 * 			up to the icmp layer to generate an icmp message to
	 * 			be snet back to the source host
	 *
	 * 2. if the check sum is fine then look up the forwarding table
	 * 		to find out the next hop for the datagram
	 * 		2.1 if ip datagram is destined for this router then figure
	 * 			out what to do with it:
	 * 			2.1.1 if it is an icmp message then pass it put to the
	 * 				icmp layer
	 * 			2.1.2 if it is anything else then also pass the datagram
	 * 				to the icmp layer and tell it to generate an icmp
	 * 				message back to the source host for destination
	 * 				protocol unreachable (not sure aobut this, double check)
	 *
	 */
}
