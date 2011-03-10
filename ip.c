#include "ip.h"
#include "icmp.h"
#include "IPDatagramBuffer.h"
#include "ARP.h"
#include "Ethernet.h"


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

void handleIPDatagram(struct sr_instance* sr, uint8_t* ip_datagram, unsigned int len, char* interface){
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


	struct ip* ip_hdr = NULL;
	//TODO: handle ip datagram
					//FIXME: can we put any ip related stuff into a class called IP.c?
					ip_hdr = (struct ip*)(ip_datagram + sizeof(struct sr_ethernet_hdr));//cast ip header
	/*
					//compute checksum
					checksum = ip_hdr->ip_sum;
					printf("checksum original %x\n", checksum);
					ip_hdr->ip_sum = 0; //checksum cleared
					checksum = csum((uint16_t*)ip_hdr, 4*(ip_hdr->ip_hl));
					printf("checksum recomputed %x\n", checksum);
					//
	*/
					switch(ip_hdr->ip_p)
					{
						case (IPPROTO_ICMP):
						{
							printf("IP packet is of type ICMP!\n");
							if(icmp_reply(sr, ip_datagram, len, interface) == 0){
								printf("Sent ICMP REPLY!\n");
							}
							break;
						}
						default:
						{
							printf("Unknown IP packet!\n");
							break;
						}
					}
}

void sendIPDatagram(struct sr_instance* sr, uint32_t next_hop_ip, char* interface, uint8_t* ip_datagram, unsigned int len){

	//if ttl is <= 1 send the datagram to icmp layer to send an icmp message
	//specifiying that the datagram has expired

	//dec ttl and recalculate the check sum

	struct sr_if* iface = sr_get_interface(sr, interface);

	uint8_t mac[ETHER_ADDR_LEN];
	int resolveStatus = resolveMAC(sr, next_hop_ip, iface, mac);

	switch(resolveStatus){
		case(ARP_RESOLVE_SUCCESS):
		{
			ethSendIPDatagram(sr, mac, ip_datagram, iface, len);
			break;
		}
		case(ARP_REQUEST_SENT):
		{
			bufferIPDatagram(sr, next_hop_ip, ip_datagram, interface, len);
			break;
		}
		case(ARP_RESOLVE_FAIL):
		{
			//TODO: tell ip layer about the bad new
			break;
		}
		default:
			break;
	}

}
