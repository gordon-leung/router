/*
 * IPDatagramBuffer.c
 *
 *  Created on: 2011-03-10
 *      Author: holman
 */

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "IPDatagramBuffer.h"
#include "sr_if.h"
#include "Ethernet.h"
#include "sr_protocol.h"


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

/*Extract the next ip datagram, along with its length, from the list
 * of datagram_buff_entry structs
 * @param sr the router instance
 * @param ip_datagram_list_ptr the pointer to the list of datagram_buff_entry
 * 		structs
 * @param len_buff_ptr the pointer to the buffer used to store the length of
 * 		the extracted datagram
 * @return the ip datagram extracted if the list is not empty, NULL otherwise
 */
static uint8_t* extractNextIPDatagram(struct sr_instance* sr, struct datagram_buff_entry** ip_datagram_list_ptr, unsigned int* len_buff_ptr);


void sendBufferedIPDatagrams(struct sr_instance* sr, uint32_t ip, uint8_t* dest_mac, struct sr_if* iface){

	struct datagram_buff_entry* ip_datagram_list = removeIPDatagramBuffer(sr, ip, iface->name);

	uint8_t* ip_datagram = NULL;
	unsigned int ip_datagram_len = 0;

	while((ip_datagram = extractNextIPDatagram(sr, &ip_datagram_list, &ip_datagram_len))){

		ethSendIPDatagram(sr, dest_mac, ip_datagram, iface, ip_datagram_len);

		free(ip_datagram);

	}

}

void handleUndeliverableBufferedIPDatagram(struct sr_instance* sr, uint32_t ip, struct sr_if* iface){

	struct datagram_buff_entry* ip_datagram_list = removeIPDatagramBuffer(sr, ip, iface->name);

	uint8_t* ip_datagram = NULL;
	unsigned int ip_datagram_len = 0;

	while((ip_datagram = extractNextIPDatagram(sr, &ip_datagram_list, &ip_datagram_len))){

		if( ((struct ip*)ip_datagram)->ip_p != IPPROTO_ICMP ){
			//only send icmp message about a ip datagram if its payload
			//is not an icmp message because we should not send icmp message
			//about another icmp message

			//TODO:call icmp to send a message back to the sender of the ip
			//datagram
		}

		free(ip_datagram);

	}

}

static uint8_t* extractNextIPDatagram(struct sr_instance* sr, struct datagram_buff_entry** ip_datagram_list_ptr, unsigned int* len_buff_ptr){

	struct datagram_buff_entry* ip_datagram_container = *ip_datagram_list_ptr;

	uint8_t* ip_datagram = NULL;

	if(ip_datagram_container){

		ip_datagram = ip_datagram_container->ip_datagram;
		assert(ip_datagram);

		*len_buff_ptr = ip_datagram_container->len;

		*ip_datagram_list_ptr = ip_datagram_container->next;

		free(ip_datagram_container);

		sr->num_datagrams_buffed--;
	}

	return ip_datagram;

}

void bufferIPDatagram(struct sr_instance* sr, uint32_t ip, uint8_t * ip_datagram, char* interface, unsigned int len){

	struct datagram_buff* buff = addNewIPDatagramBufferIfNotExist(sr, ip, interface);

	addIPDatagramToBuffer(ip_datagram, len, buff);

	sr->num_datagrams_buffed++;
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

		sr->num_of_datagram_buffers --;
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
		buff = (struct datagram_buff*)malloc(sizeof(struct datagram_buff));
		assert(buff);

		buff->next = sr->datagram_buff_list;
		if(sr->datagram_buff_list){
			sr->datagram_buff_list->previous = buff;
		}
		buff->previous = NULL;
		sr->datagram_buff_list = buff;

		buff->ip = ip;
		buff->iface_name = interface;
		buff->datagram_buff_entry_list = NULL;

		sr->num_of_datagram_buffers++;
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
