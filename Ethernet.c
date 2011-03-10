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
#include "ip.h"

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

/*Buffers the ip datagram while it is waiting for arp resolution
 * @param sr the router instance
 * @param ip the ip addr used to resolve the mac addr
 * @param ip_datagram the ip datagram
 * @param interface the name of the interface where the eth frame
 * 		encapsulating the ip datagram is to be sent
 * @param len the size of the ip datagram in bytes
 */
static void bufferIPDatagram(struct sr_instance* sr, uint32_t ip, uint8_t * ip_datagram, char* interface, unsigned int len);

/*Sends an IP datagram
 * @param sr router instance
 * @param dest_mac the mac address of the target interface
 * @param ip_datagram the ip datagram to be sent
 * @param interface the name of the interface on the router
 * 		where the eth frame encapsulating the ip datagram
 * 		is to be sent from
 * @param len the size of the ip datagram in bytes
 */
static void sendIPDatagram(struct sr_instance* sr, uint8_t* dest_mac, uint8_t * ip_datagram, struct sr_if* iface, unsigned int len);

/*Try to find a buffer that matches the ip and interface
 * @param sr the router instance
 * @param ip the ip addr of the target interface where the
 * 		frame encapsulating the ip datagram is to be sent to
 * @param interface the name of the interface on this router
 * 		where the frame is to be sent from
 * @return the buffer if the matching buffer is fround, NULL
 * 		otherwise
 */
static struct datagram_buff* findIPDatagramBuffer(struct sr_instance* sr, uint32_t ip, char* interface);

/*Create a new buffer for the ip and interface pair if one
 * doesn't already exist
 * @param sr the router instance
 * @param ip the ip addr of the target interface where the
 * 		frame is to be sent to
 * @param interface the name of the interface on this router
 * 		where the fame is to be sent from
 * @return either the matching buffer that already exist or
 * 		a new one just created
 */
static struct datagram_buff* addNewIPDatagramBufferIfNotExist(struct sr_instance* sr, uint32_t ip, char* interface);

/*Add the ip datagram into the buffer
 * @param ip_datagram the ip datagram to be added into the buffer
 * @param len the size of the ip datagram in bytes
 * @param buff the buffer where the ip datagram is to be added
 */
static void addIPDatagramToBuffer(uint8_t * ip_datagram, unsigned int len, struct datagram_buff* buff);

/*Remove the ip datagram buffer that matches the ip and interface
 * pair if it exists and return the list of ip datagrams in that
 * buffer.
 * @param sr the router instance
 * @param ip the ip addr of the target interface where the buffered
 * 		datagrams are to be sent to
 * @param interface the name of the interface on this router where
 * 		the buffered ip datagram are to be sent from
 * @return the list of buffered ip datagrams if the match buffer
 * 		exists, NULL otherwise
 */
static struct datagram_buff_entry* removeIPDatagramBuffer(struct sr_instance* sr, uint32_t ip, char* interface);


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
				//FIXME: passing in the ip eth_fram and interface name is a hack
				//change it to pass in the ip datagram and not pass in the interface
				handleIPDatagram(sr, ethPacket, len, interface);
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

void ethSendArpRequest(struct sr_instance* sr, uint8_t * arp_request, struct sr_if* iface, unsigned int len){

	//encapsulate the arp_request in a eth frame
	uint8_t* eth_frame = encapsulate(arp_request, len);

	uint8_t dest_mac[ETHER_ADDR_LEN];
	setBroadCastMAC(dest_mac);

	sendEthFrame_arp(sr, dest_mac, eth_frame, iface, len);

	if(eth_frame){
		free(eth_frame);
	}
}

void ethSendIPDatagram(struct sr_instance* sr, uint32_t ip, uint8_t * ip_datagram, char* interface, unsigned int len){

	struct sr_if* iface = sr_get_interface(sr, interface);

	uint8_t mac[ETHER_ADDR_LEN];
	int resolveStatus = resolveMAC(sr, ip, iface, mac);

	switch(resolveStatus){
		case(ARP_RESOLVE_SUCCESS):
		{
			sendIPDatagram(sr, mac, ip_datagram, iface, len);
			break;
		}
		case(ARP_REQUEST_SENT):
		{
			bufferIPDatagram(sr, ip, ip_datagram, interface, len);
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

void ethSendBufferedIPDatagrams(struct sr_instance* sr, uint32_t ip, uint8_t* dest_mac, struct sr_if* iface){

	struct datagram_buff_entry* ip_datagram_list = removeIPDatagramBuffer(sr, ip, iface->name);

	if(ip_datagram_list){

		struct datagram_buff_entry* ip_datagram_container = ip_datagram_list;

		while(ip_datagram_container){

			uint8_t* ip_datagram = ip_datagram_container->ip_datagram;
			unsigned int ip_datagram_len = ip_datagram_container->len;

			sendIPDatagram(sr, dest_mac, ip_datagram, iface, ip_datagram_len);

			if(ip_datagram){
				free(ip_datagram);
			}

			struct datagram_buff_entry* current_container = ip_datagram_container;

			ip_datagram_container = current_container->next;

			free(current_container);

		}
	}
	else{
		//nothing to send... yae
	}

}

static void bufferIPDatagram(struct sr_instance* sr, uint32_t ip, uint8_t * ip_datagram, char* interface, unsigned int len){

	struct datagram_buff* buff = addNewIPDatagramBufferIfNotExist(sr, ip, interface);

	addIPDatagramToBuffer(ip_datagram, len, buff);

}

static struct datagram_buff_entry* removeIPDatagramBuffer(struct sr_instance* sr, uint32_t ip, char* interface){

	struct datagram_buff* buff = findIPDatagramBuffer(sr, ip, interface);

	struct datagram_buff_entry* ip_datagram_list = NULL;

	if(buff){

		//buff exist in the list of buffers. remove it from the list

		ip_datagram_list = buff->datagram_buff_entry_list;

		struct datagram_buff* previous_buff = buff->previous;

		struct datagram_buff* next_buff = buff->next;

		if(previous_buff){
			previous_buff->next = next_buff;
		}
		else{
			//buff is currently at the front of the list of buffers
			sr->datagram_buff_list = next_buff;
		}

		if(next_buff){
			next_buff->previous = previous_buff;
		}

		free(buff);
	}

	return ip_datagram_list;

}

static void addIPDatagramToBuffer(uint8_t * ip_datagram, unsigned int len, struct datagram_buff* buff){

	//make a copy of the ip datagram to be stored into the buffer
	uint8_t* ip_datagram_cpy = (uint8_t*) malloc(len);
	assert(ip_datagram_cpy);
	memcpy(ip_datagram_cpy, ip_datagram, len);

	struct datagram_buff_entry* buff_entry = (struct datagram_buff_entry*) malloc(sizeof(struct datagram_buff_entry));
	buff_entry->ip_datagram = ip_datagram_cpy;
	buff_entry->len = len;
	buff_entry->next = buff->datagram_buff_entry_list;
	buff->datagram_buff_entry_list = buff_entry;
}

static struct datagram_buff* addNewIPDatagramBufferIfNotExist(struct sr_instance* sr, uint32_t ip, char* interface){

	struct datagram_buff* buff = findIPDatagramBuffer(sr, ip, interface);

	if(!buff){//no buffer for this ip addr yet. create it
		struct datagram_buff* buff = (struct datagram_buff*)malloc(sizeof(struct datagram_buff));
		buff->next = sr->datagram_buff_list;
		if(sr->datagram_buff_list){
			sr->datagram_buff_list->previous = buff;
		}
		buff->previous = NULL;
		sr->datagram_buff_list = buff;
		buff->datagram_buff_entry_list = NULL;
	}

	return buff;
}

static struct datagram_buff* findIPDatagramBuffer(struct sr_instance* sr, uint32_t ip, char* interface){

	struct datagram_buff* buff = sr->datagram_buff_list;

	while(buff){
		if((buff->ip == ip) && (strcmp(interface, buff->iface_name)==0)){
			return buff;
		}
		buff = buff->next;
	}

	//not found
	return NULL;
}

static uint8_t* encapsulate(uint8_t* payload, unsigned int payload_len){
	uint8_t* eth_frame = (uint8_t*) malloc(sizeof(struct sr_ethernet_hdr) + payload_len);
	assert(eth_frame);

	//copy the payload into the data field of the eth frame
	memcpy(eth_frame + sizeof(struct sr_ethernet_hdr), payload, payload_len);

	return eth_frame;
}

static void sendIPDatagram(struct sr_instance* sr, uint8_t* dest_mac, uint8_t * ip_datagram, struct sr_if* iface, unsigned int len){
	//encapsulate the ip datagram in a eth frame
	uint8_t* eth_frame = encapsulate(ip_datagram, len);

	struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)eth_frame;
	eth_hdr->ether_type = htons(ETHERTYPE_IP);

	sendEthFrame(sr, dest_mac, eth_frame, iface, len);

	if(eth_frame){
		free(eth_frame);
	}
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
