/*
 * ARP.c
 *
 *  Created on: 2011-03-06
 *      Author: holman
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>

#include "ARP.h"
#include "Ethernet.h"
#include "sr_protocol.h"
#include "Defs.h"
#include "sr_router.h"

/*prints the arp header for debugging purposes.*/
//static void printArpPacketHdr(struct sr_arphdr* arphdr);

/*Updates the arp table with the ip mac pair passed in
 * @return 1 if the entry exists in the arp table thus update succeeds
 * 	return 0 if no entry with matching ip exists in the arp table
 */
static int updateArpEntry(struct ip_eth_arp_tbl_entry* arp_tbl, const uint32_t ip, uint8_t* mac);

/*Find the arp table entry whose ip field matches the ip passed in
 * if one exists
 * @return the arp table whose ip field matches the ip passed in
 * 	return NULL if no such entry if no such entry exists
 */
static struct ip_eth_arp_tbl_entry* findArpEntry(struct ip_eth_arp_tbl_entry* arp_tbl, const uint32_t ip);

/*Add and entry into the arp table based on the ip and mac passed in*/
static void addArpEntry(struct sr_if* iface, const uint32_t ip, uint8_t* mac);

/*Reusing the eth frame for the arp request to convert it into
 * the arp response.
 */
static void setupArpResponse(struct sr_arphdr* arphdr, struct sr_if* iface);

/*Checks to see if the arp entry has expired.
 * @return 1 if the arp entry is expired, o otherwise
 */
static int isArpEntryExpired(struct ip_eth_arp_tbl_entry* arp_entry);

/*Deleting an entry from the arp table.
 * @param arp_entry the entry to be deleted
 * @parm iface the interface where the arp table resides.
 */
static void deleteArpEntry(struct ip_eth_arp_tbl_entry* arp_entry, struct sr_if* iface);

/*Populate the fields of the arphdr struct for the arp request
 * @param arphdr the buffer for the arp hdr for the arp request
 * @param ip the target interface ip addr
 * @param iface the interface on the router where the
 * 		arp request is sent from.
 */
static void setupArpRequest(struct sr_arphdr* arphdr, const uint32_t ip, struct sr_if* iface);


void handleArpPacket(struct sr_instance* sr, uint8_t * ethPacket, struct sr_if* iface){

	struct sr_arphdr* arphdr = (struct sr_arphdr*)(ethPacket + sizeof(struct sr_ethernet_hdr));

	assert(arphdr);

	//printArpPacketHdr(arphdr);

	if(ntohs(arphdr->ar_hrd) != ARPHDR_ETHER){
		//hardware address space is not of type ethernet
		//nothing to do with it here
		return;
	}

	if(arphdr->ar_hln != ETHER_ADDR_LEN){
		//hardware address is not 6 bytes long
		//nothing to do with it here
		return;
	}

	if(ntohs(arphdr->ar_pro) != ETHERTYPE_IP){
		//upper layer protocol is not ip
		//nothing to do with it here
		return;
	}

	if(arphdr->ar_pln != IP_ADDR_LEN){
		//ip addr is not 4 bytes long
		//nothing to do with it here
		return;
	}

	int updated_arp_entry = updateArpEntry(iface->ip_eth_arp_tbl, arphdr->ar_sip, arphdr->ar_sha);

	if(arphdr->ar_tip != iface->ip){
		//this arp packet is not targeted for the ip bounded to the interface
		//nothing more to do with the arp packet
		return;
	}

	// now that the arp packet is targeted for the ip bound to the interface
	// that received the packet we first add an arp entry for the source
	// interface if the arp table didn't get updated with the src ip and mac
	// because there isn't an entry in the arp table that has the ip field
	// matching the ip addr of the src interface.
	if(!updated_arp_entry){
		addArpEntry(iface, arphdr->ar_sip, arphdr->ar_sha);
	}

	if(ntohs(arphdr->ar_op) == ARP_REQUEST){
		setupArpResponse(arphdr, iface);
		sendEthFrame_arp(sr, arphdr->ar_tha, ethPacket, iface, sizeof(struct sr_arphdr));
	}

}

uint8_t* resolve(struct sr_instance* sr, const uint32_t ip, struct sr_if* iface){

	struct ip_eth_arp_tbl_entry* arp_entry = findArpEntry(iface->ip_eth_arp_tbl, ip);

	const int arpEntryExpired = isArpEntryExpired(arp_entry);

	if(arpEntryExpired){
		//if the arp table entry has expired we delete it from
		//the arp table. Three advantages in doing this:
		//	1. free up memory
		//	2. old entries for interfaces that got assigned
		//		new ip address don't stay in arp table forever
		//	3. when the corresponding arp response come back
		//		it will always be put to the front of the list
		//		so this reduce the lookup time for most recently
		//		resoved arp entries.
		deleteArpEntry(arp_entry, iface);
	}

	if((!arp_entry) || arpEntryExpired){
		//need to resolve by sending an arp request. do it!
		struct sr_arphdr* arp_request = (struct sr_arphdr*) malloc(sizeof(struct sr_arphdr));
		assert(arp_request);
		setupArpRequest(arp_request, ip, iface);
		sendArpRequest(sr, (uint8_t*) arp_request, iface, sizeof(struct sr_arphdr));
		if(arp_request){
			free(arp_request);
		}
		return NULL;
	}
	else{
		return arp_entry->addr;
	}
}

static void setupArpRequest(struct sr_arphdr* arphdr, const uint32_t ip, struct sr_if* iface){

	arphdr->ar_hln = ETHER_ADDR_LEN;

	arphdr->ar_hrd = htons(ARPHDR_ETHER);

	arphdr->ar_op = htons(ARP_REQUEST);

	arphdr->ar_pln = IP_ADDR_LEN;

	arphdr->ar_pro = htons(ETHERTYPE_IP);

	MACcpy(arphdr->ar_sha, iface->addr);

	arphdr->ar_sip = iface->ip;

	setBroadCastMAC(arphdr->ar_tha);

	arphdr->ar_tip = ip;

}

static void deleteArpEntry(struct ip_eth_arp_tbl_entry* arp_entry, struct sr_if* iface){

	assert(arp_entry);

	struct ip_eth_arp_tbl_entry* previous_entry = arp_entry->previous;
	struct ip_eth_arp_tbl_entry* next_entry = arp_entry->next;

	if(previous_entry){
		previous_entry->next = next_entry;
	}
	else{
		//the entry to be deleted is at the beginning
		//of the linked list
		iface->ip_eth_arp_tbl = next_entry;
	}

	if(next_entry){
		next_entry->previous = previous_entry;
	}

	free(arp_entry);

}

static int isArpEntryExpired(struct ip_eth_arp_tbl_entry* arp_entry){
	return difftime(time(NULL), arp_entry->last_modified) >= ARP_TBL_ENTRY_TTL;
}

static void setupArpResponse(struct sr_arphdr* arphdr, struct sr_if* iface){

	arphdr->ar_tip = arphdr->ar_sip;
	MACcpy(arphdr->ar_tha, arphdr->ar_sha);

	arphdr->ar_sip = iface->ip;
	MACcpy(arphdr->ar_sha, iface->addr);

	arphdr->ar_op = htons(ARP_REPLY);
}

static void addArpEntry(struct sr_if* iface, const uint32_t ip, uint8_t* mac){

	struct ip_eth_arp_tbl_entry* arp_entry = (struct ip_eth_arp_tbl_entry*) malloc(sizeof(struct ip_eth_arp_tbl_entry));

	MACcpy(arp_entry->addr, mac);
	time(&(arp_entry->last_modified));

	//append the new entry to the front of the linked list
	//representing the arp table
	struct ip_eth_arp_tbl_entry* first_arp_entry = iface->ip_eth_arp_tbl;
	if(first_arp_entry){
		first_arp_entry->previous = arp_entry;
	}
	arp_entry->next = first_arp_entry;
	arp_entry->previous = NULL;
	iface->ip_eth_arp_tbl = arp_entry;

}

static int updateArpEntry(struct ip_eth_arp_tbl_entry* arp_tbl, const uint32_t ip, uint8_t* mac){
	struct ip_eth_arp_tbl_entry* arp_entry = findArpEntry(arp_tbl, ip);
	if(arp_entry == NULL){
		return FALSE;
	}
	else{
		MACcpy(arp_entry->addr, mac);
		time(&(arp_entry->last_modified));
		return TRUE;
	}
}

static struct ip_eth_arp_tbl_entry* findArpEntry(struct ip_eth_arp_tbl_entry* arp_tbl, const uint32_t ip){
	while(arp_tbl){
		if(arp_tbl->ip == ip){
			return arp_tbl;
		}
		arp_tbl = arp_tbl->next;
	}
	//can't find an entry with matching ip
	return NULL;
}

/*static void printArpPacketHdr(struct sr_arphdr* arphdr){
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
}*/
