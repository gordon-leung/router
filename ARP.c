/*
 * ARP.c
 *
 *  Created on: 2011-03-06
 *      Author: holman
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include "ARP.h"
#include "Ethernet.h"
#include "sr_protocol.h"

static void printArpPacketHdr(struct sr_arphdr* arphdr);
static int handleArpRequest(struct sr_arphdr* arphdr);
static int handleArpReply();

int handleArpPacket(struct sr_arphdr* arphdr, struct sr_if* iface){

	assert(arphdr);

	printArpPacketHdr(arphdr);

	switch(ntohs(arphdr->ar_op)){

		case (ARP_REQUEST):
			break;
		case (ARP_REPLY):
			break;
		default:
			break;

	}

	return 0;
}

static int handleArpRequest(struct sr_arphdr* arphdr){

}

static int handleArpReply(){

}

static void printArpPacketHdr(struct sr_arphdr* arphdr){
	printf("\n");
	printf("ARP header:\n");
	printf("Hrd addr space: %d\n", ntohs(arphdr->ar_hrd));
	printf("Proto addr space: %d\n", ntohs(arphdr->ar_pro));
	printf("Hrd addr length: %d\n", arphdr->ar_hln);
	printf("Proto addr length: %d\n", arphdr->ar_pln);
	printf("arp op: %d\n", ntohs(arphdr->ar_op));

	printf("Src hrd addr: ");
	printEthAddr(arphdr->ar_sha);
	printf("\n");

	char dotted_ip[INET_ADDRSTRLEN]; //should contain dotted-decimal format of interface ip
	inet_ntop(AF_INET, &(arphdr->ar_sip), dotted_ip, INET_ADDRSTRLEN);
	dotted_ip[INET_ADDRSTRLEN] = '\0';
	printf("Src ip: %s\n", dotted_ip);

	printf("Target hrd addr: ");
	printEthAddr(arphdr->ar_tha);
	printf("\n");

	inet_ntop(AF_INET, &(arphdr->ar_tip), dotted_ip, INET_ADDRSTRLEN);
	dotted_ip[INET_ADDRSTRLEN] = '\0';
	printf("Target ip: %s\n", dotted_ip);
	printf("\n");
}
