#include "ip.h"
#include "icmp.h"
#include "IPDatagramBuffer.h"
#include "ARP.h"
#include "Ethernet.h"
#include "sr_rt.h"
#include "sr_if.h"


/*Lookup the routing table and try to find and entry with the subnet
 * that has the longest prefix match against the destination ip addr
 *@param the router instance
 *@param dest_host_ip the ip addr of the destination host
 *@return the routing table entry with the subnet having the longest
 *		prefix match against the destination host ip addr, or NULL
 *		if no such entry exists.
 */
static struct sr_rt* lookupRoutingTable(struct sr_instance* sr, uint32_t dest_host_ip);

/*Forward the packet to the next hop
 * @param sr the router instance
 * @param eth_frame the eth frame encapsulating the ip datagram to
 * 		be sent
 * @param ip_datagram the ip datagram to be sent
 * @param ip_datagram_len the size of the ip datagram in bytes
 */
static void forward(struct sr_instance* sr, uint8_t* eth_frame, uint8_t* ip_datagram, unsigned int ip_datagram_len);

/*Process the ip datagram for which this router is the destination host
 * @param sr the router instance
 * @param eth_frame the eth frame encapsulating the ip datagram
 * @param ip_datagram the ip datagram
 * @param ip_datagram_len the size of the ip datagram in bytes
 */
static void processIPDatagramDestinedForMe(struct sr_instance* sr, uint8_t* eth_frame, uint8_t* ip_datagram, unsigned int ip_datagram_len);

/*Check to see if this router is the destination host for the
 * ip datagram
 *@param sr the router instance
 *@param dest_host_ip the destination host ip
 *@return 1 if this router is the destination host, 0 otherwise
 */
static int ipDatagramDestinedForMe(struct sr_instance* sr, uint32_t dest_host_ip);


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

void handleIPDatagram(struct sr_instance* sr, uint8_t* eth_frame, uint8_t* ip_datagram, unsigned int ip_datagram_len){
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

	struct ip* ip_hdr = (struct ip*)ip_datagram;

	//TODO: check ip header and checksum

	if(ipDatagramDestinedForMe(sr, ip_hdr->ip_dst.s_addr)){
		processIPDatagramDestinedForMe(sr, eth_frame, ip_datagram, ip_datagram_len);
	}
	else if(ip_hdr->ip_ttl != 0){
		//ttl greater than 0, we can try to forward it
		forward(sr, eth_frame, ip_datagram, ip_datagram_len);
	}
	else{
		//ip datagram is not destined for me and
		//ttl has expired.
		//TODO: call icmp to send an icmp message back
		//to sending host saying time exceeded
	}

}

static void processIPDatagramDestinedForMe(struct sr_instance* sr, uint8_t* eth_frame, uint8_t* ip_datagram, unsigned int ip_datagram_len){

	struct ip* ip_hdr = (struct ip*)ip_datagram;

	if(ip_hdr->ip_p == IPPROTO_ICMP){
		//TODO: call icmp to handle the icmp message received
		printf("IP packet is of type ICMP!\n");
		if(icmp_reply(sr, eth_frame, ip_datagram_len + 14, "eth0") == 0){
			printf("Sent ICMP REPLY!\n");
		}
	}
	else{
		//This router can't handle any transport layer segment
		//destined for it other than icmp
		//TODO: call icmp to send a message back to sending host
		//saying that dest protocol not reachable.
	}

}

static int ipDatagramDestinedForMe(struct sr_instance* sr, uint32_t dest_host_ip){

	struct sr_if* iface = sr->if_list;

	while(iface){
		if(iface->ip == dest_host_ip){
			return TRUE;
		}
		iface = iface->next;
	}

	return FALSE;

}

static void forward(struct sr_instance* sr, uint8_t* eth_frame, uint8_t* ip_datagram, unsigned int ip_datagram_len){

	struct ip* ip_hdr = (struct ip*)ip_datagram;

	struct sr_rt* rt_entry_with_longest_prefix = lookupRoutingTable(sr, ip_hdr->ip_dst.s_addr);

	if(rt_entry_with_longest_prefix){
		uint32_t next_hop_ip = rt_entry_with_longest_prefix->gw.s_addr;
		char* interface = rt_entry_with_longest_prefix->interface;
		sendIPDatagram(sr, next_hop_ip, interface, ip_datagram, eth_frame, ip_datagram_len);
	}
	else{
		//no matching routing table entry returned.
		//unable to forward this packet
		//TODO send an icmp message back to sending host.
	}

}

static struct sr_rt* lookupRoutingTable(struct sr_instance* sr, uint32_t dest_host_ip){

	struct sr_rt* current_rt_entry = sr->routing_table;

	uint32_t longest_prefix = 0;
	struct sr_rt* rt_entry_with_longest_prefix = NULL;

	while(current_rt_entry){

		uint32_t masked_rt_dest_ip = ntohl(current_rt_entry->dest.s_addr) & ntohl(current_rt_entry->mask.s_addr);
		uint32_t masked_dest_host_ip =  ntohl(dest_host_ip) & ntohl(current_rt_entry->mask.s_addr);

		if((masked_rt_dest_ip == masked_dest_host_ip) && (masked_dest_host_ip >= longest_prefix)){
			longest_prefix = masked_dest_host_ip;
			rt_entry_with_longest_prefix = current_rt_entry;
		}

		current_rt_entry = current_rt_entry->next;

	}

	return rt_entry_with_longest_prefix;

}

void sendIPDatagram(struct sr_instance* sr, uint32_t next_hop_ip, char* interface, uint8_t* ip_datagram, uint8_t* eth_frame, unsigned int ip_datagram_len){

	//if ttl equals 0 send the datagram to icmp layer to send an icmp message
	//specifiying that the datagram has expired

	//dec ttl and recalculate the check sum

	struct sr_if* iface = sr_get_interface(sr, interface);

	uint8_t mac[ETHER_ADDR_LEN];
	int resolveStatus = resolveMAC(sr, next_hop_ip, iface, mac);

	switch(resolveStatus){
		case(ARP_RESOLVE_SUCCESS):
		{
			if(eth_frame){
				//the ip datagram is already encapsulated in a eth frame
				sendEthFrameContainingIPDatagram(sr, mac, eth_frame, iface, ip_datagram_len);
			}
			else{
				ethSendIPDatagram(sr, mac, ip_datagram, iface, ip_datagram_len);
			}
			break;
		}
		case(ARP_REQUEST_SENT):
		{
			bufferIPDatagram(sr, next_hop_ip, ip_datagram, interface, ip_datagram_len);
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
