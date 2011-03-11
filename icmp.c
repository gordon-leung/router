#include <stdlib.h>
#include <string.h>
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
		uint8_t*					temp_icmp_hdr = NULL;
		unsigned long temp_addr = 0;

/*TEST CODE
		struct sockaddr_in sa;
		sa.sin_addr.s_addr = sr->routing_table->gw.s_addr;//assign binary value to s_addr
		char dotted_ip[INET_ADDRSTRLEN]; //should contain dotted-decimal format of interface ip
		inet_ntop(AF_INET, &(sa.sin_addr), dotted_ip, INET_ADDRSTRLEN);
		printf("interface : %s\n",dotted_ip);
END TEST CODE*/

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
		temp_icmp_hdr = create_icmp(sr, (uint8_t*)ip_hdr, ICMP_REPLY, 0);
		memcpy(icmp_hdr, temp_icmp_hdr,(ntohs(ip_hdr->ip_len) - 4*(ip_hdr->ip_hl)));
		free(temp_icmp_hdr);
//END ICMP REPLY MODIFICATION

/*TEST CODE
		temp_icmp_hdr = create_icmp(sr, (uint8_t*)ip_hdr, ICMP_DEST_UNREACHABLE, ICMP_HOST_UNREACHABLE);
		memcpy(icmp_hdr, temp_icmp_hdr,4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
		printf("type: %x\n", icmp_hdr->icmp_type);
		printf("code: %x\n", icmp_hdr->icmp_code);
		printf("checksum: %x\n", icmp_hdr->icmp_checksum);
END TEST code*/

		//send it out
		return sr_send_packet(sr, packet, len, interface);
}

uint8_t * create_icmp(struct sr_instance* sr, uint8_t * ip_datagram, int type, int code){
		struct ip* ip_hdr = (struct ip*)ip_datagram; //cast ip header
		struct icmphdr* icmp_hdr = NULL;

		switch(type)
		{
			case ICMP_REPLY:
			{
				//allocate memory
				icmp_hdr = (struct icmphdr*) malloc(ntohs(ip_hdr->ip_len) - 4*(ip_hdr->ip_hl));

				//copy from ip_datagram
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
				icmp_hdr = (struct icmphdr*) malloc(4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
				//set to zero
				memset(icmp_hdr,0,4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
				//set fields
				icmp_hdr->icmp_type = type;
				icmp_hdr->icmp_code = code;
				memcpy((uint8_t*)icmp_hdr+ICMP_START_ERROR, (uint8_t*)ip_hdr, 4*(ip_hdr->ip_hl)+ICMP_NUM_IP_BYTES);
				icmp_hdr->icmp_checksum = csum((uint16_t*)icmp_hdr, 4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
				break;
			}
/*
			case ICMP_TIME_EXCEEDED:
			{
				//allocate memory
				icmp_hdr = (struct icmphdr*) malloc(4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
				//set to zero
				memset(icmp_hdr,0,4*(ip_hdr->ip_hl) + ICMP_ERROR_SIZE);
				//set fields
				icmp_hdr->icmp_type = type;
				icmp_hdr->icmp_code = code;
				memcpy((uint8_t*)icmp_hdr+ICMP_START_ERROR, (uint8_t*)ip_hdr, 4*(ip_hdr->ip_hl)+ICMP_NUM_IP_BYTES);
				break;
			}
*/
			default :
			{
				printf("ICMP type not recognized");
			}
		}

		return (uint8_t*)icmp_hdr;
}

void ipDatagramTimeExceeded(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len){

	//icmp fields to be set:
	//type = 11
	//code = 0

	//dest_ip = the ip_datagram's sender's ip addr

	//allocate memory/buffer for just the icmp message, not the ip datagram and not the eth frame
	//i.e. just allocate enough memory for the type field, code field, checksum field, unused field
	//and the internet header + 64 bits of the ip_datagram passed in.
	//It should be at least 28 bytes but since ip datagram's header can be more than 20 bytes long
	//due to options, the size need to be calculated dynamically

	//for the icmp message, fill in the type field, code field, and make sure the 4 bytes of unused
	//space are all 0

	//copy the ip_datagram's headder and the first 8 bytes of ip_datagram data into the icmp message

	//recalculate the checksum

	// call sendIcmpMessage(struct sr_instance* sr, uint8_t* icmp_message, unsigned int icmp_msg_len, uint32_t dest_ip);

	//free the buffer allocated for the icmp message

}

void destinationUnreachable(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len, unsigned short code){

	//icmp fields to be set:
	//type = 3
	//code = the code param passed in

	//dest_ip = the ip_datagram's sender's ip addr

	//refer to ipDatagramTimeExceeded(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len)
	//to see what to do next;
}

void parameterProblem(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len, unsigned short code, uint8_t pointer){

	//icmp fields to be set:
	//type = 12
	//code = the code param passed in
	//pointer = the pointer arg passed in

	//dest_ip = the ip_datagram's sender's ip addr

	//refer to ipDatagramTimeExceeded(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len)
	//to see what to do next;
}

void handleIcmpMessageReceived(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len){

	//do check sum
	//if check sum failed then just drop it and return, nothing more to do here

	//for the icmp message encapsulated in this ip_datagram, make sure the type is 8
	//for echo request. we only handle echo request icmp, aka ping, message and for
	//any other types of icmp message we simply drop it and return

	//icmp fields to be set
	//type = 0
	//code = 0

	//dest_ip = the ip_datagram's sender's ip addr

	//here we don't need to construct a new icmp message, just reuse the one in the
	//ip_datagram. u have to calculate base on the ip datagram header size to see
	//where the icmp message begins

	//fill in the type field, the code field and leave the rest the same

	//recalculate checksum

	// call sendIcmpMessage(struct sr_instance* sr, uint8_t* icmp_message, unsigned int icmp_msg_len, uint32_t dest_ip);

	//note: no need to free any buffer here since we didn't allocate any in this
	//function
}
