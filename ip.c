#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ip.h"
#include "icmp.h"
#include "IPDatagramBuffer.h"
#include "ARP.h"
#include "Ethernet.h"
#include "sr_rt.h"
#include "sr_if.h"


//static void printIPDatagram(struct ip* ip_hdr, uint8_t* ip_datagram, unsigned int ip_datagram_len, char* title);

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

/*Checks the header of the ip datagram to determine if the ip
 * datagram should be dropped by the router
 * @param ip_hdr the ip header to be checked
 * @return 1 if the ip datagram should be dropped, 0 otherwise
 */
static int ipDatagramShouldBeDropped(struct ip ip_hdr);

/*Decrement the ttl field in the ip datagrams header and
 * recalculate the checksum
 * @param ip_hdr the header of the ip datagram
 */
static void ip_dec_ttl(struct ip* ip_hdr);

/*Set up the header for the ip datagram encapsulating an icmp
 * message
 *@param ip_hdr the ip header
 *@param ip_datagram_total_len the size of the entire ip
 *		datagram in bytes
 *@param src_ip the source ip addr, which should be one of
 *		the ip addr assigned to this router
 *@param dest_ip the destination host's ip addr where the
 *		icmp message is to be sent to
 */
static void setupIPHeaderForICMP(struct ip* ip_hdr, uint16_t ip_datagram_total_len, uint32_t src_ip, uint32_t dest_ip);


void handleIPDatagram(struct sr_instance* sr, uint8_t* eth_frame, uint8_t* ip_datagram, unsigned int ip_datagram_len){

	/*this is the entry point into the ip layer. This method
	 * will be called by the ethernet layer when it received an ip
	 * datagram that is targeted for this router.
	 *
	 * A few things to do here:
	 * 	1. Check to see if this router can handle this ip datagram by
	 * 		checking ip datagram's header:
	 * 			1.1 see if the checksum is correct
	 * 			1.2 see if it is ipv4
	 * 			1.3 make sure there is no options fields set
	 * 			1.4 make sure the size ip datagram size is at
	 * 				least as big as the header
	 * 		If this check fail then the ip datagram is dropped
	 *
	 *	2. Check to see if the ip datagram is destined for this router
	 *		2.1 if it is then try to handle it:
	 *			2.1.1 if the ip datagram encapsulates an icmp message
	 *					then call icmp and it the ip datagram for handling
	 *			2.1.2 if the ip datagram encapsulate packets
	 *					for protocol other than icmp then call icmp
	 *					to handle the dest protocol unreacable situation
	 *
	 *	3. If the ip datagram is not destined for this router
	 *		3.1 see if the ttl is > 0
	 *			3.1.1 if yes then try to forward it
	 *			3.1.2 if no then call icmp to handle the time exceeded
	 *					situcation for the ip datagram
	 *
	 */

	struct ip* ip_hdr = (struct ip*)ip_datagram;

	//printIPDatagram(ip_hdr, ip_datagram, ip_datagram_len, "Received IP datagram:");

	if(ipDatagramShouldBeDropped(*ip_hdr)){

		sr->num_ip_datagrams_dropped++;

		//the check sum check didn't pass or the ip
		//datagram is of the type that can't be handled
		//by this router, drop it.
		return;
	}

	if(ipDatagramDestinedForMe(sr, ip_hdr->ip_dst.s_addr)){
		processIPDatagramDestinedForMe(sr, eth_frame, ip_datagram, ip_datagram_len);
	}
	else if(ip_hdr->ip_ttl > 1){
		//ttl greater than 1, we can try to forward it
		forward(sr, eth_frame, ip_datagram, ip_datagram_len);
	}
	else{
		//ip datagram is not destined for me and
		//ttl has expired, so can't be forwarded
		ipDatagramTimeExceeded(sr, ip_datagram, ip_datagram_len);

		sr->num_ip_datagrams_dropped++;
	}

}

static void processIPDatagramDestinedForMe(struct sr_instance* sr, uint8_t* eth_frame, uint8_t* ip_datagram, unsigned int ip_datagram_len){

	struct ip* ip_hdr = (struct ip*)ip_datagram;

	if(ip_hdr->ip_p == IPPROTO_ICMP){
		//the ip datagram contains an icmp message
		//call the icmp component to handle it
		handleIcmpMessageReceived(sr, ip_datagram, ip_datagram_len);
	}
	else if( (ip_hdr->ip_p == IPPROTO_UDP) || (ip_hdr->ip_p == IPPROTO_TCP) ){
		//for ping to work properly we need to use this even
		//though the router is not running UDP or TCP
		destinationUnreachable(sr, ip_datagram, ip_datagram_len, ICMP_CODE_PORT_UNREACHABLE);
	}
	else{
		//This router can't handle any transport layer segment
		//destined for it other than icmp
		destinationUnreachable(sr, ip_datagram, ip_datagram_len, ICMP_CODE_PROTOCOL_UNREACHABLE);
	}

	//for now consider it dropped because we are not counting
	//ip datagram sent that contains an icmp message generated
	//by this router
	sr->num_ip_datagrams_dropped++;
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
		//the destination subnet is not reachable.
		destinationUnreachable(sr, ip_datagram, ip_datagram_len, ICMP_CODE_NET_UNREACHABLE);
		sr->num_ip_datagrams_dropped++;
	}

}

static struct sr_rt* lookupRoutingTable(struct sr_instance* sr, uint32_t dest_host_ip){

	struct sr_rt* current_rt_entry = sr->routing_table;

	//this variable stores the current longest ip prefix
	//matching the dest_host_ip
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

	ip_dec_ttl((struct ip*) ip_datagram);

	struct sr_if* iface = sr_get_interface(sr, interface);

	uint8_t mac[ETHER_ADDR_LEN];
	int resolveStatus = resolveMAC(sr, next_hop_ip, iface, mac);

	switch(resolveStatus){
		case(ARP_RESOLVE_SUCCESS):
		{

			//hack, hack, hack. Single threaded router and fast links
			//are a bad combination for download large files. It seems
			//the application server can blast data at very high speed
			//but when packets are lost, most of the time the dup ack
			//don't arrive to the application server until it's too late
			//i.e. application server has sent a TCP FIN segment
			//The solution, slow down the sending of each large packet
			//by small amount of time.
			if(ip_datagram_len > IP_DATAGRAM_SIZE_THRESHOLD){
				//usleep(WAIT_TIME);
			}

			//printIPDatagram((struct ip*)ip_datagram, ip_datagram, ip_datagram_len, "Sending IP datagram:");
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
			printf("ip packet buffered\n");
			break;
		}
		case(ARP_RESOLVE_FAIL):
		{
			//bad news, the next hop is unreachable. call icmp to handle
			//this ip datagram, as well as all the ones buffered waiting
			//to be delivered to the same next hop.
			destinationUnreachable(sr, ip_datagram, ip_datagram_len, ICMP_CODE_NET_UNREACHABLE);

			sr->num_ip_datagrams_dropped++;

			handleUndeliverableBufferedIPDatagram(sr, next_hop_ip, iface);
			break;
		}
		default:
			break;
	}

}


void ipSendIcmpMessage(struct sr_instance* sr, uint8_t* icmp_message, unsigned int icmp_msg_len, uint32_t dest_ip){

	assert(icmp_msg_len >= ICMP_HDR_LEN);
	assert(icmp_message);
	assert(sr);
	assert(dest_ip);

	//so no source ip addr is specified, for now we will use
	//the ip addr of one of the interface on this router that
	//happens to be the first one ont eh if_list. Don't think
	//this would cause any trouble at the moment but ideally it
	//should be the ip addr of the interface that received the
	//ip datagram which caused this icmp message to be sent
	struct sr_if* iface = sr->if_list;
	assert(iface);
	ipSendIcmpMessageWithSrcIP(sr, icmp_message, icmp_msg_len, dest_ip, iface->ip);

}

void ipSendIcmpMessageWithSrcIP(struct sr_instance* sr, uint8_t* icmp_message, unsigned int icmp_msg_len, uint32_t dest_ip, uint32_t src_ip){

	assert(icmp_msg_len >= ICMP_HDR_LEN);
	assert(icmp_message);
	assert(sr);
	assert(src_ip);
	assert(dest_ip);

	//before we do anything, find out what is the next hop ip
	//is for this ip datagram as well as which interface on
	//this router to use to send out the eth frame encapsulating
	//this ip datagram
	struct sr_rt* rt_entry_with_longest_prefix = lookupRoutingTable(sr, dest_ip);

	if(!rt_entry_with_longest_prefix){
		//looks like there is no way to send this icmp message
		//too bad, nothing to do anymore, just return
		return;
	}

	uint16_t ip_datagram_total_len = sizeof(struct ip) + icmp_msg_len;
	uint8_t* ip_datagram = (uint8_t*)malloc(ip_datagram_total_len);
	assert(ip_datagram);

	setupIPHeaderForICMP((struct ip*)ip_datagram, ip_datagram_total_len, src_ip, dest_ip);

	//copy the icmp message into the data field of the ip datagram
	memcpy(ip_datagram + sizeof(struct ip), icmp_message, icmp_msg_len);

	uint32_t next_hop_ip = 	rt_entry_with_longest_prefix->gw.s_addr;
	char* interface = rt_entry_with_longest_prefix->interface;
	sendIPDatagram(sr, next_hop_ip, interface, ip_datagram, NULL, ip_datagram_total_len);

	if(ip_datagram){
		free(ip_datagram);
	}
}

static void setupIPHeaderForICMP(struct ip* ip_hdr, uint16_t ip_datagram_total_len, uint32_t src_ip, uint32_t dest_ip){

	ip_hdr->ip_v = IPV4_VERSION;
	ip_hdr->ip_hl = DEFAULT_IP_HEADER_LEN;
	ip_hdr->ip_tos = DEFAULT_IP_TOS;
	ip_hdr->ip_len = htons(ip_datagram_total_len);

	ip_hdr->ip_id = htons(DEFAULT_IP_ID);
	ip_hdr->ip_off = htons(DEFAULT_IP_FRAGMENT);

	ip_hdr->ip_ttl = DEFAULT_IP_TTL;
	ip_hdr->ip_p = IPPROTO_ICMP;

	ip_hdr->ip_src.s_addr = src_ip;

	ip_hdr->ip_dst.s_addr = dest_ip;

}

static void ip_dec_ttl(struct ip* ip_hdr){

	//sanity check, make sure we don't send
	//packet with ttl = 0
	assert(ip_hdr->ip_ttl > 1);

	ip_hdr->ip_ttl--;
	ip_hdr->ip_sum = 0; //clear checksum
	ip_hdr->ip_sum = csum((uint16_t*)ip_hdr, 4*(ip_hdr->ip_hl)); //recompute
}


static int ipDatagramShouldBeDropped(struct ip ip_hdr){

	if(ntohs(ip_hdr.ip_len) < 20){//datagram too short.
		return TRUE;
	}
	if(ntohs(ip_hdr.ip_len) > 1500){//datagram too long.
		return TRUE;
	}
	if(ip_hdr.ip_v != IPV4_VERSION){//not IP_V4
		return TRUE;
	}
	if(ip_hdr.ip_hl > 5){//datagram has options set, drop it
		return TRUE;
	}
	uint16_t checksum = ip_hdr.ip_sum;
	ip_hdr.ip_sum = 0; //clear checksum
	//recompute and check
	if(checksum != csum((uint16_t*) &ip_hdr, 4*(ip_hdr.ip_hl))){
		return TRUE;
	}

	return FALSE;
}

/*static void printIPDatagram(struct ip* ip_hdr, uint8_t* ip_datagram, unsigned int ip_datagram_len, char* title){

	if(ntohs(ip_hdr->ip_len) != ip_datagram_len){
		printf("Inconsistent ip datagram len. vns told me: %d\n", ip_datagram_len);
	}

	printf("**********************************\n");
	printf("%s\n", title);
	printf("IP header:\n");
	printf("IP version: %d\n",ip_hdr->ip_v);
	printf("IP header length: %d\n", ip_hdr->ip_hl);
	printf("TOS: %d\n", ip_hdr->ip_tos);
	printf("Total length: %d\n", ntohs(ip_hdr->ip_len));
	printf("Frag ID: %d\n", ntohs(ip_hdr->ip_id));
	printf("Frag Offset: %x\n", ntohs(ip_hdr->ip_off));
	printf("TTL: %d\n", ip_hdr->ip_ttl);
	printf("Protocol: %d\n", ip_hdr->ip_p);
	printf("Checksum: %d\n", ip_hdr->ip_sum);
	char dotted_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip_hdr->ip_src), dotted_ip, INET_ADDRSTRLEN);
	printf("Source IP: %s\n", dotted_ip);
	inet_ntop(AF_INET, &(ip_hdr->ip_dst), dotted_ip, INET_ADDRSTRLEN);
	printf("Destination IP: %s\n", dotted_ip);
	printf("Data:\n");
	uint8_t* ip_data = (uint8_t*)(ip_datagram + sizeof(struct ip));
	unsigned int byte_index = 0;
	unsigned int data_size = ip_datagram_len - sizeof(struct ip);
	while(byte_index < data_size){
		if(byte_index == 0){
		}
		else if((byte_index % 8) == 0){
			printf("\n");
		}
		else if((byte_index % 4) == 0){
			printf("\t");
		}
		else{
			printf(" ");
		}
		printf("%*x", 2, *(uint8_t*)(ip_data + byte_index));
		byte_index++;
	}
	printf("\n");
	printf("**********************************\n");
}*/
