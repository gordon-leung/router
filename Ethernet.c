/*
 * Ethernet.c
 *
 *  Created on: 2011-03-06
 *      Author: holman
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "Ethernet.h"
#include "sr_protocol.h"
#include "sr_if.h"
#include "ARP.h"
#include "Defs.h"

//static void printPacketHeader(struct sr_ethernet_hdr* eth_hdr);
//static void printEthMac(struct sr_instance* sr);

static int isFrameForMe(struct sr_instance* sr, struct sr_ethernet_hdr* eth_hdr, struct sr_if* iface);

static void sendEthFrame(struct sr_instance* sr, uint8_t* dest_mac, uint8_t * eth_frame, struct sr_if* iface, unsigned int payload_len);

static uint8_t* encapsulate(uint8_t* payload, unsigned int payload_len);

void handleEthPacket(struct sr_instance* sr,
        uint8_t * ethPacket,
        unsigned int len,
        char* interface){

	assert(sr);
	assert(ethPacket);
	assert(interface);

	//testSendArpRequest(sr);

	//FIGURE OUT WHAT TO DO WITH INCOMING ETH PACKET
	struct sr_ethernet_hdr* eth_hdr = NULL;
	struct ip* ip_hdr = NULL;
	eth_hdr = (struct sr_ethernet_hdr*)ethPacket;//cast ethernet header
	struct sr_if* iface = sr_get_interface(sr, interface); //the interface where the frame is received

	unsigned short ether_type = ntohs(eth_hdr->ether_type);
	uint16_t checksum = -1;

	//printEthMac(sr);
	//printPacketHeader(eth_hdr);

	switch(ether_type){
		case (ETHERTYPE_ARP): //ARP PACKET!
		{
			//if it is a eth arp packet we send it to arp component to see if any useful info
			//can be extracted regarded if the eth frame is meant for us.
			printf("Got ARP PACKET!\n");
			handleArpPacket(sr, ethPacket, iface);
			break;
		}

		case (ETHERTYPE_IP): //IP PACKET!
		{
			printf("Got IP packet!\n");

			if(isFrameForMe(sr, eth_hdr, iface)){
				//TODO: handle ip datagram
				//FIXME: can we put any ip related stuff into a class called IP.c?
				ip_hdr = (struct ip*)(ethPacket + sizeof(struct sr_ethernet_hdr));//cast ip header
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
						if(icmp_reply(sr, ethPacket, len, interface) == 0){ 
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
			else{
				//Just drop the eth frame because it is not even
				//targetted for me.
				printf("eth frame not for me\n");
			}

			break;
		}
		default:
		{
			printf("Unknown packet type: %d!\n", ether_type );
			break;
		}
	}

}

void sendArpRequest(struct sr_instance* sr, uint8_t * arp_request, struct sr_if* iface, unsigned int len){

	//encapsulate the arp_request in a eth frame
	uint8_t* eth_frame = encapsulate(arp_request, len);

	uint8_t dest_mac[ETHER_ADDR_LEN];
	setBroadCastMAC(dest_mac);

	sendEthFrame_arp(sr, dest_mac, eth_frame, iface, len);

	if(eth_frame){
		free(eth_frame);
	}
}

void sendIPDatagram(struct sr_instance* sr, uint32_t ip, uint8_t * ip_datagram, char* interface, unsigned int len){

	//encapsulate the ip datagram in a eth frame
	uint8_t* eth_frame = encapsulate(ip_datagram, len);

	struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)eth_frame;
	eth_hdr->ether_type = htons(ETHERTYPE_IP);

	struct sr_if* iface = sr_get_interface(sr, interface);

	uint8_t mac[ETHER_ADDR_LEN];
	int resolveStatus = resolveMAC(sr, ip, iface, mac);

	switch(resolveStatus){
		case(ARP_RESOLVE_SUCCESS):
		{
			sendEthFrame(sr, mac, eth_frame, iface, len);
			break;
		}
		case(ARP_REQUEST_SENT):
		{
			break;
		}
		case(ARP_RESOLVE_FAIL):
		{
			break;
		}
		default:
			break;
	}

}

static uint8_t* encapsulate(uint8_t* payload, unsigned int payload_len){
	uint8_t* eth_frame = (uint8_t*) malloc(sizeof(struct sr_ethernet_hdr) + payload_len);
	assert(eth_frame);

	//copy the payload into the data field of the eth frame
	memcpy(eth_frame + sizeof(struct sr_ethernet_hdr), payload, payload_len);

	return eth_frame;
}

void sendEthFrame_arp(struct sr_instance* sr, uint8_t* dest_mac, uint8_t * eth_frame, struct sr_if* iface, unsigned int payload_len){
	struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)eth_frame;
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	sendEthFrame(sr, dest_mac, eth_frame, iface, payload_len);
}

static void sendEthFrame(struct sr_instance* sr, uint8_t* dest_mac, uint8_t * eth_frame, struct sr_if* iface, unsigned int payload_len){

	struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)eth_frame;

	MACcpy(eth_hdr->ether_dhost, dest_mac);
	MACcpy(eth_hdr->ether_shost, iface->addr);

	unsigned int frame_len = sizeof(struct sr_ethernet_hdr) + payload_len;

	sr_send_packet( sr, eth_frame, frame_len, iface->name);
}

int MACcmp(const uint8_t* macAddr1, const uint8_t* macAddr2){
	for(int i=0; i<ETHER_ADDR_LEN; i++){
		if( macAddr1[i] != macAddr2[i]){
			return FALSE;
		}
	}
	return TRUE;
}

void MACcpy(uint8_t* dest, uint8_t* src){
	for(int i=0; i<ETHER_ADDR_LEN; i++){
		dest[i] = src[i];
	}
}

void setBroadCastMAC(uint8_t* mac_buff){
	for(int i=0; i<ETHER_ADDR_LEN; i++){
		mac_buff[i] = BROAD_CAST_MAC;
	}
}

int isBroadCastMAC(const uint8_t* macAddr){
	for(int i=0; i<ETHER_ADDR_LEN; i++){
		if( macAddr[i] != BROAD_CAST_MAC){
			return FALSE;
		}
	}
	return TRUE;
}

void printEthAddr(uint8_t* eth_hdr){
	printf("%x", eth_hdr[0]);
	for(int i=1; i<ETHER_ADDR_LEN; i++){
		printf("-%x", eth_hdr[i]);
	}
}

static int isFrameForMe(struct sr_instance* sr, struct sr_ethernet_hdr* eth_hdr, struct sr_if* iface){
	return isBroadCastMAC(eth_hdr->ether_dhost) || MACcmp(iface->addr, eth_hdr->ether_dhost);
}

/*static void printPacketHeader(struct sr_ethernet_hdr* eth_hdr){
	printf("\n");
	printf("eth frame header: \n");

	printf("DEST_ETH_ADDR: ");
	printEthAddr(eth_hdr->ether_dhost);
	printf("\n");

	printf("SRC_ETH_ADDR: ");
	printEthAddr(eth_hdr->ether_shost);
	printf("\n");

	printf("ETHER_TYPE: %d", ntohs(eth_hdr->ether_type));
	printf("\n");
}*/

/*static void printEthMac(struct sr_instance* sr){
	printf("%s", sr->if_list->name);
	printf(" mac: ");
	printEthAddr(sr->if_list->addr);
}*/
