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


/*--------------------------------------------------------------------- 
 * Method: icmp_reply(...)
 * Return: 0 on success
 *
 * Replies to an ICMP Request
 *---------------------------------------------------------------------*/
int icmp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
		struct ip*    ip_hdr = NULL;
		uint8_t*			icmp_hdr = NULL;
		uint8_t*			temp_icmp_hdr = NULL;
		unsigned long temp_addr = 0;

//BEGIN ICMP REPLY MODIFICATION
		//ETHERNET HEADER CHANGES
		struct sr_ethernet_hdr* e_hdr = NULL;//init
		struct sr_if* iface = sr_get_interface(sr, interface); //packet is from which interface?
		e_hdr = (struct sr_ethernet_hdr*)packet;//cast ethernet header
		
		for(int i=0; i<ETHER_ADDR_LEN; i++){
			e_hdr->ether_dhost[i] = e_hdr->ether_shost[i];
			e_hdr->ether_shost[i] = iface->addr[i];
		}

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
		icmp_hdr = (packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip));
		temp_icmp_hdr = create_icmp(sr, (uint8_t*)ip_hdr, ICMP_REPLY, 0);
		memcpy(icmp_hdr, temp_icmp_hdr,(ntohs(ip_hdr->ip_len) - 4*(ip_hdr->ip_hl)));		
//END ICMP REPLY MODIFICATION
//TEST CODE
//		temp_icmp_hdr = create_icmp(sr, (uint8_t*)ip_hdr, ICMP_DEST_UNREACHABLE, ICMP_HOST_UNREACHABLE);
//		memcpy(icmp_hdr, temp_icmp_hdr,4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
//		printf("type: %x\n", icmp_hdr->icmp_type);
//		printf("code: %x\n", icmp_hdr->icmp_code);
//		printf("checksum: %x\n", icmp_hdr->icmp_checksum);
/*
		printf("num of bytes copied %d\n", 4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
		printf("num of bytes copied %d\n", ntohs(ip_hdr->ip_len) - 4*(ip_hdr->ip_hl));
		printf("empty data: %x\n", *(icmp_hdr));			//first byte
		printf("empty data: %x\n", *(icmp_hdr+1));		//second byte
		printf("empty data: %x\n", *(icmp_hdr+2));
		printf("empty data: %x\n", *(icmp_hdr+3));
		printf("empty data: %x\n", *(icmp_hdr+4));
		printf("empty data: %x\n", *(icmp_hdr+5));
		printf("empty data: %x\n", *(icmp_hdr+6));
		printf("empty data: %x\n", *(icmp_hdr+7));
		printf("empty data: %x\n", *(icmp_hdr+8));		//ip header
*/
//END TEST code
/*TEST CODE
		struct sockaddr_in sa;
		sa.sin_addr.s_addr = sr->routing_table->gw.s_addr;//assign binary value to s_addr
		char dotted_ip[INET_ADDRSTRLEN]; //should contain dotted-decimal format of interface ip
		inet_ntop(AF_INET, &(sa.sin_addr), dotted_ip, INET_ADDRSTRLEN);
		printf("interface : %s\n",dotted_ip);
END TEST CODE*/

		//send it out
		free(temp_icmp_hdr);
		return sr_send_packet(sr, packet, len, interface);
}


uint8_t* create_icmp(struct sr_instance* sr, uint8_t * ip_datagram, int type, int code){
		struct ip* ip_hdr = (struct ip*)ip_datagram; //cast ip header
		struct icmphdr* icmp_hdr = NULL;
		int data_size = 0;
		int ip_data_size = ntohs(ip_hdr->ip_len) - 4*(ip_hdr->ip_hl);
		if(ip_data_size < ICMP_ERROR_SIZE){
			data_size = ip_data_size;
		}
		else{
			data_size = ICMP_ERROR_SIZE;
		}

		switch(type)
		{
			case ICMP_REPLY:
			{
				//allocate memory
				icmp_hdr = (struct icmphdr*)(uint8_t*) malloc(ntohs(ip_hdr->ip_len) - 4*(ip_hdr->ip_hl));

				//copy data from ip_datagram
				memcpy(icmp_hdr, (uint8_t*)ip_hdr+4*(ip_hdr->ip_hl), (ntohs(ip_hdr->ip_len) - 4*(ip_hdr->ip_hl)));

				//set fields in icmp hdr
				icmp_hdr->icmp_type = type;
				//recompute icmp checksum
				icmp_hdr->icmp_checksum = 0;
				icmp_hdr->icmp_checksum = csum((uint16_t*)icmp_hdr, (ntohs((ip_hdr->ip_len)) - 4*(ip_hdr->ip_hl)));
				break;
			}
			case ICMP_DEST_UNREACHABLE:
			{
				//allocate memory
				icmp_hdr = (struct icmphdr*)(uint8_t*) malloc(4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
				//set to zero
				memset(icmp_hdr,0,4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
				//set fields
				icmp_hdr->icmp_type = type;
				icmp_hdr->icmp_code = code;
				//copy the ip header and first 8 bytes from ip datagram if there is 8 bytes of data
				memcpy((uint8_t*)icmp_hdr+ICMP_START_ERROR, (uint8_t*)ip_hdr, 4*(ip_hdr->ip_hl)+data_size);
				icmp_hdr->icmp_checksum = csum((uint16_t*)icmp_hdr, 4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
				break;
			}
			case ICMP_TIME_EXCEEDED:
			{
				//allocate memory
				icmp_hdr = (struct icmphdr*)(uint8_t*) malloc(4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
				//set to zero
				memset(icmp_hdr,0,4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
				//set fields
				icmp_hdr->icmp_type = type;
				icmp_hdr->icmp_code = code;
				//copy the ip header and first 8 bytes from ip datagram if there is 8 bytes of data
				memcpy((uint8_t*)icmp_hdr+ICMP_START_ERROR, (uint8_t*)ip_hdr, 4*(ip_hdr->ip_hl)+data_size);
				icmp_hdr->icmp_checksum = csum((uint16_t*)icmp_hdr, 4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
				break;
			}
			default :
			{
				printf("ICMP type not recognized");
			}
		}
		return (uint8_t*)icmp_hdr;
}

void ipDatagramTimeExceeded(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len){

/*	//icmp fields to be set:
	//type = 11
	//code = 0

	//allocate memory/buffer for just the icmp message, not the ip datagram and not the eth frame
	//i.e. just allocate enough memory for the type field, code field, checksum field, unused field
	//and the internet header + 64 bits of the ip_datagram passed in.

		struct ip*    ip_hdr = NULL;
		uint8_t*			temp_icmp_hdr = NULL;
//BEGIN ICMP TIMEEXCEEDED MODIFICATION
		//ETHERNET HEADER CHANGES
//		ethernet_swap_src_dest(sr, packet, interface);
		ip_hdr = (struct ip*)ip_datagram;
		temp_icmp_hdr = create_icmp(sr, ip_datagram, ICMP_TIME_EXCEEDED, ICMP_TIMEOUT);
//END ICMP TIMEEXCEEDED MODIFICATION

	// call sendIcmpMessage(struct sr_instance* sr, uint8_t* icmp_message, unsigned int icmp_msg_len, uint32_t dest_ip);
		sendIcmpMessage(sr, temp_icmp_hdr, 2*sizeof(struct ip) + ICMP_ERROR_SIZE, ip_hdr->ip_src.s_addr);
	//free the buffer allocated for the icmp message
	free(temp_icmp_hdr);
*/
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
}

void destinationUnreachable(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len, unsigned short code){
		/*
		struct ip*    ip_hdr = NULL;
		uint8_t*			temp_icmp_hdr = NULL;
		ip_hdr = (struct ip*)ip_datagram;
		temp_icmp_hdr = create_icmp(sr, ip_datagram, ICMP_DEST_UNREACHABLE, code);
		// call sendIcmpMessage(struct sr_instance* sr, uint8_t* icmp_message, unsigned int icmp_msg_len, uint32_t dest_ip);
		sendIcmpMessage(sr, temp_icmp_hdr, 2*sizeof(struct ip) + ICMP_ERROR_SIZE, ip_hdr->ip_src.s_addr);
		//free the buffer allocated for the icmp message
		free(temp_icmp_hdr);
		*/

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

	sendIcmpMessage(sr, icmp_msg, icmp_msg_len, dest_ip);

	if(icmp_msg){
		free(icmp_msg);
	}
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
}

static int checksumCorrect(struct icmphdr* icmp_hdr, uint16_t* icmp_msg, unsigned int icmp_msg_len){

	uint16_t checksum = icmp_hdr->icmp_checksum;
	icmp_hdr->icmp_checksum = 0;
	uint16_t calculated_checksum = csum(icmp_msg, icmp_msg_len);

	//lets try not to change the content of the icmp message
	icmp_hdr->icmp_checksum = checksum;

	return checksum == calculated_checksum;
}
