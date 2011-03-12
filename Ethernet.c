/*
 * Ethernet.c
 *
 *  Created on: 2011-03-06
 *      Author: holman
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Ethernet.h"
#include "sr_protocol.h"
#include "sr_if.h"
#include "ARP.h"
#include "ip.h"
#include "test.h"

//static void printPacketHeader(struct sr_ethernet_hdr* eth_hdr);
//static void printEthMac(struct sr_instance* sr);

/*Determine if the eth frame if targeted for the interface where
 * the frame is received from
 * @param sr the router instance
 * @param eth_hdr the header of the eth frame received
 * @param iface the interface where the fame is received
 * @return 1 if the frame is targeted for the interface where
 * 		the frame is received, 0 otherwise
 */
static int isFrameForMe(struct sr_instance* sr, struct sr_ethernet_hdr* eth_hdr, struct sr_if* iface);

/*Sends a eth frame
 * @param sr the router instance
 * @param dest_mac the mac of the target interface where the eth
 * 		frame is to be sent to
 * @param iface the interface on this router where the eth frame
 * 		is to be sent from
 * @param payload_len the size of the payload in bytes *
 */
static void sendEthFrame(struct sr_instance* sr, uint8_t* dest_mac, uint8_t * eth_frame, struct sr_if* iface, unsigned int payload_len);

/*create an eth frame and encapsulate the payload into its data field
 *@param payload the payload
 *@param payload_len the size of the payload in bytes
 *@return the eth frame
 */
static uint8_t* encapsulate(uint8_t* payload, unsigned int payload_len);



void handleEthFrame(struct sr_instance* sr,
        uint8_t * eth_frame,
        unsigned int len,
        char* interface){

	assert(sr);
	assert(eth_frame);
	assert(interface);

	//testSendArpRequest(sr);
	printf("\nnum of datagram buffers (before): %d\n", sr->num_of_datagram_buffers);
	printf("\nnum datagram buffered (before): %d\n", sr->num_datagrams_buffed);

	struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)eth_frame;//cast ethernet header
	struct sr_if* iface = sr_get_interface(sr, interface); //the interface where the frame is received

	unsigned short ether_type = ntohs(eth_hdr->ether_type);

	//printEthMac(sr);
	//printPacketHeader(eth_hdr);

	//FIGURE OUT WHAT TO DO WITH INCOMING ETH PACKET
	switch(ether_type){
		case (ETHERTYPE_ARP): //ARP PACKET!
		{
			//if it is a eth arp packet we send it to arp component to see if any useful info
			//can be extracted regarded if the eth frame is meant for us.
			printf("Got ARP PACKET!\n");
			handleArpPacket(sr, eth_frame, iface);
			break;
		}

		case (ETHERTYPE_IP): //IP PACKET!
		{
			printf("Got IP packet!\n");

			if(isFrameForMe(sr, eth_hdr, iface)){

				uint8_t* ip_datagram = eth_frame + sizeof(struct sr_ethernet_hdr);
				unsigned int ip_datagram_len = len - sizeof(struct sr_ethernet_hdr);
				handleIPDatagram(sr, eth_frame, ip_datagram, ip_datagram_len);

			}
			else{
				//Nothing to do, frame is not for me
				//just drop it.
				printf("eth frame not for me, dropping it\n");
			}

			break;
		}
		default:
		{
			printf("Unknown packet type: %d!\n", ether_type );
			break;
		}
	}

	//printf("\nnum of datagram buffers (after): %d\n", sr->num_of_datagram_buffers);
	//printf("\nnum datagram buffered (after): %d\n", sr->num_datagrams_buffed);

}

void ethSendArpRequest(struct sr_instance* sr, uint8_t * arp_request, struct sr_if* iface, unsigned int len){

	//encapsulate the arp_request in a eth frame
	uint8_t* eth_frame = encapsulate(arp_request, len);

	uint8_t dest_mac[ETHER_ADDR_LEN];
	setBroadCastMAC(dest_mac);

	sendEthFrameContainingArpMsg(sr, dest_mac, eth_frame, iface, len);

	if(eth_frame){
		free(eth_frame);
	}
}

void ethSendIPDatagram(struct sr_instance* sr, uint8_t* dest_mac, uint8_t * ip_datagram, struct sr_if* iface, unsigned int len){

	//encapsulate the ip datagram in a eth frame
	uint8_t* eth_frame = encapsulate(ip_datagram, len);
	assert(eth_frame);

	sendEthFrameContainingIPDatagram(sr, dest_mac, eth_frame, iface, len);

	if(eth_frame){
		free(eth_frame);
	}

}

void sendEthFrameContainingIPDatagram(struct sr_instance* sr, uint8_t* dest_mac, uint8_t * eth_frame, struct sr_if* iface, unsigned int payload_len){
	struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)eth_frame;
	eth_hdr->ether_type = htons(ETHERTYPE_IP);

	sendEthFrame(sr, dest_mac, eth_frame, iface, payload_len);
}

static uint8_t* encapsulate(uint8_t* payload, unsigned int payload_len){
	uint8_t* eth_frame = (uint8_t*) malloc(sizeof(struct sr_ethernet_hdr) + payload_len);
	assert(eth_frame);

	//copy the payload into the data field of the eth frame
	memcpy(eth_frame + sizeof(struct sr_ethernet_hdr), payload, payload_len);

	return eth_frame;
}

void sendEthFrameContainingArpMsg(struct sr_instance* sr, uint8_t* dest_mac, uint8_t * eth_frame, struct sr_if* iface, unsigned int payload_len){
	struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)eth_frame;
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	sendEthFrame(sr, dest_mac, eth_frame, iface, payload_len);
}

static void sendEthFrame(struct sr_instance* sr, uint8_t* dest_mac, uint8_t * eth_frame, struct sr_if* iface, unsigned int payload_len){

	struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)eth_frame;

	MACcpy(eth_hdr->ether_dhost, dest_mac);
	MACcpy(eth_hdr->ether_shost, iface->addr);

	//printPacketHeader(eth_hdr);

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
