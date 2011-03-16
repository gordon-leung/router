#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "icmp.h"
#include "ip.h"

/*Checks to see if the icmp checksum of the icmp received
 * is correct
 * @param icmp_hdr the header of the icmp message
 * @param icmp_msg the icmp message recieved
 * @param icmp_msg_len the size of the icmp message in bytes
 * @return 1 if no error is detected, 0 otherwise
 */
static int checksumCorrect(struct icmphdr* icmp_hdr, uint16_t* icmp_msg, unsigned int icmp_msg_len);

/*Calculate the size, in bytes,  of the icmpp message to be constructed
 * for the ip datagram causing the icmp message to be constructed
 * @param ip_datagram_len the size, in bytes, of the ip datagram
 * 		causing the icmp message to be constructed
 * @return the size in bytes of the icmp message to be constructed
 * 		for the ip datagram
 */
static unsigned int calculateIcmpMsgLen(unsigned int ip_datagram_len);

/*Copy the header and at most 64 bits of the ip datagrame data into
 * the icmp message following immediately after the header
 * @param icmp_msg the icmp_msg
 * @param ip_datagram the ip datagram
 * @param icmp_msg_len the size of the icmp message in bytes
 */
static void copyIPHeaderAndDataToIcmpMsg(uint8_t* icmp_msg, uint8_t * ip_datagram, unsigned int icmp_msg_len);

/*Setup the header of the icmp message and calcualte the checksum
 * @param icmp_msg the icmp_msg whose header we want to setup
 * @param icmp_msg_len the size of the icmp message in bytes
 * @param type the value of the type field of the icmp message
 * @param code the value for the code field of the icmp message
 */
static void setupIcmpHeader(uint8_t* icmp_msg, unsigned int icmp_msg_len, uint8_t type, uint8_t code);

/*Checks to see if the ip datagram contains an icmp message
 * @param ip_datagram the ip datagram to be checked
 * @return 1 if the ip datagram contains an icmp message
 * 		0 otherwise
 */
static int ipDatagramContainsIcmpMsg(uint8_t* ip_datagram);


void ipDatagramTimeExceeded(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len){

	if(ipDatagramContainsIcmpMsg(ip_datagram)){
		//the ip datagram that cause triggers this icmp message
		//to be generated encapsulates another icmp message
		//we are not sending an icmp message about another
		//icmp message.
		return;
	}

	unsigned int icmp_msg_len = calculateIcmpMsgLen(ip_datagram_len);
	uint8_t* icmp_msg = (uint8_t*) malloc(icmp_msg_len);
	bzero(icmp_msg, icmp_msg_len);

	copyIPHeaderAndDataToIcmpMsg(icmp_msg, ip_datagram, icmp_msg_len);

	//setup icmp header, includes calculating checksum
	setupIcmpHeader(icmp_msg, icmp_msg_len, ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TTL_EXCEEDED);

	//the source ip of the original ip datagram becomes the destination
	//ip of this icmp message
	uint32_t dest_ip = ((struct ip*)ip_datagram)->ip_src.s_addr;

	sendIcmpMessage(sr, icmp_msg, icmp_msg_len, dest_ip);

	if(icmp_msg){
		free(icmp_msg);
	}

	sr->num_icmp_messages_created++;
}

void destinationUnreachable(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len, unsigned short code){

	if(ipDatagramContainsIcmpMsg(ip_datagram)){
		//the ip datagram that cause triggers this icmp message
		//to be generated encapsulates another icmp message
		//we are not sending an icmp message about another
		//icmp message.
		return;
	}

	assert(sr);
	assert(ip_datagram);
	assert( (code == ICMP_CODE_NET_UNREACHABLE)
			|| (code == ICMP_CODE_HOST_UNREACHABLE)
			|| (code == ICMP_CODE_PROTOCOL_UNREACHABLE)
			|| (code == ICMP_CODE_PORT_UNREACHABLE));

	unsigned int icmp_msg_len = calculateIcmpMsgLen(ip_datagram_len);
	uint8_t* icmp_msg = (uint8_t*) malloc(icmp_msg_len);
	bzero(icmp_msg, icmp_msg_len);

	copyIPHeaderAndDataToIcmpMsg(icmp_msg, ip_datagram, icmp_msg_len);

	//setup icmp header, includes calculating checksum
	setupIcmpHeader(icmp_msg, icmp_msg_len, ICMP_TYPE_DESTINATION_UNREACHABLE, code);

	//the source ip of the original ip datagram becomes the destination
	//ip of this icmp message
	uint32_t dest_ip = ((struct ip*)ip_datagram)->ip_src.s_addr;

	if((code == ICMP_CODE_PROTOCOL_UNREACHABLE) || (code == ICMP_CODE_PORT_UNREACHABLE)){
		//in this case this router is the destination of the
		//original ip datagram so the source ip for this icmp message
		//should be the same as the destination ip of the original
		//ip datagram
		uint32_t src_ip = ((struct ip*)ip_datagram)->ip_dst.s_addr;
		sendIcmpMessageWithSrcIP(sr, icmp_msg, icmp_msg_len, dest_ip, src_ip);
	}
	else{
		sendIcmpMessage(sr, icmp_msg, icmp_msg_len, dest_ip);
	}

	if(icmp_msg){
		free(icmp_msg);
	}

	sr->num_icmp_messages_created++;
}

static void setupIcmpHeader(uint8_t* icmp_msg, unsigned int icmp_msg_len, uint8_t type, uint8_t code){

	struct icmphdr* icmp_hdr = (struct icmphdr*)icmp_msg;

	icmp_hdr->icmp_type = type;
	icmp_hdr->icmp_code = code;

	icmp_hdr->icmp_checksum = 0;
	icmp_hdr->icmp_checksum = (uint16_t)csum((uint16_t*)icmp_msg, icmp_msg_len);
}

static unsigned int calculateIcmpMsgLen(unsigned int ip_datagram_len){

	unsigned int icmp_msg_len = ICMP_HDR_LEN;

	if( (ip_datagram_len - sizeof(struct ip)) >= MAX_IP_DATA_LEN){
		icmp_msg_len += (sizeof(struct ip) + MAX_IP_DATA_LEN);
	}
	else{
		icmp_msg_len += ip_datagram_len;
	}

	return icmp_msg_len;
}

static int ipDatagramContainsIcmpMsg(uint8_t* ip_datagram){
	return (((struct ip*)(ip_datagram))->ip_p == IPPROTO_ICMP);
}

static void copyIPHeaderAndDataToIcmpMsg(uint8_t* icmp_msg, uint8_t * ip_datagram, unsigned int icmp_msg_len){
	memcpy((uint8_t*)(icmp_msg+ICMP_HDR_LEN), ip_datagram, icmp_msg_len - ICMP_HDR_LEN);
}

void handleIcmpMessageReceived(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len){

	assert(sr);
	assert(ip_datagram);

	if(ip_datagram_len < (sizeof(struct ip) + ICMP_HDR_LEN)){
		//the ip datagram is too small to be to have a valid header
		//and coontain a valid icmp message. can't process it, return
		return;
	}

	uint8_t* icmp_msg = ip_datagram + sizeof(struct ip);
	struct icmphdr* icmp_hdr = (struct icmphdr*)icmp_msg;
	unsigned int icmp_msg_len = ip_datagram_len - sizeof(struct ip);

	if(!checksumCorrect(icmp_hdr, (uint16_t*)icmp_msg, icmp_msg_len)){
		//the calculated checksum is not the same as the checksum
		//in the icmp message, drop it
		return;
	}

	if(icmp_hdr->icmp_type != ICMP_TYPE_ECHO_REQUEST){
		//the icmp message we received is not a echo
		//request, this router currently can only handle
		//icmp echo request. We just return and drop the
		//ip datagram
		return;
	}

	//the ip of the source of the icmp echo request become the
	//ip of the destination of the ip datagram used for sending
	//this icmp echo reply and the ip of the destination of the
	//echo request becomes the ip of the source for the ip
	//datagram used to send this icmp echo reply
	struct ip* ip_hdr = (struct ip*) ip_datagram;
	uint32_t dest_ip = ip_hdr->ip_src.s_addr;
	uint32_t src_ip = ip_hdr->ip_dst.s_addr;

	//setting up the icmp header for the echo reply
	icmp_hdr->icmp_type = ICMP_TYPE_ECHO_REPLY;
	icmp_hdr->icmp_checksum = 0;
	icmp_hdr->icmp_checksum = (uint16_t)csum((uint16_t*)icmp_msg, icmp_msg_len);

	sendIcmpMessageWithSrcIP(sr, icmp_msg, icmp_msg_len, dest_ip, src_ip);

	sr->num_icmp_messages_created++;
}

static int checksumCorrect(struct icmphdr* icmp_hdr, uint16_t* icmp_msg, unsigned int icmp_msg_len){

	uint16_t checksum = icmp_hdr->icmp_checksum;
	icmp_hdr->icmp_checksum = 0;
	uint16_t calculated_checksum = csum(icmp_msg, icmp_msg_len);

	//lets try not to change the content of the icmp message
	icmp_hdr->icmp_checksum = checksum;

	return checksum == calculated_checksum;
}
