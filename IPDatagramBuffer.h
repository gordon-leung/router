/*
 * IPDatagramBuffer.h
 *
 *  Created on: 2011-03-10
 *      Author: holman
 */
#include <stdint.h>
#include "sr_router.h"


/*A buffer that contain a linked list of ip
 * datagrams an the ip addr and interface
 * they are associate to. Buffers are also
 * chained together in a doublely linked list
 */
struct datagram_buff{
	uint32_t ip;
	char* iface_name;
	struct datagram_buff_entry* datagram_buff_entry_list;
	struct datagram_buff* next;
	struct datagram_buff* previous;
};

/*Used as a container in the datagram buffer
 * to hold an ip datagram and its size. Used
 * as a linked list to chain together all the
 * ip datagrams in the buffer
 */
struct datagram_buff_entry{
	uint8_t* ip_datagram;
	unsigned int len;
	struct datagram_buff_entry* next;
};


/*Send any ip datagrams that has been buffered because they
 * are waiting for arp resolution
 *@param sr the router instance
 *@param ip the ip addr of the target interface where the frame
 *		is to be sent to
 *@param dest_mac the mac addr of the interface where the frame
 *		is to be sent to
 *@param iface the interface on this router where the frame is to
 *		be sent from
 */
void sendBufferedIPDatagrams(struct sr_instance* sr, uint32_t ip, uint8_t* dest_mac, struct sr_if* iface);

/*Buffers the ip datagram while it is waiting for arp resolution
 * @param sr the router instance
 * @param ip the ip addr used to resolve the mac addr
 * @param ip_datagram the ip datagram
 * @param interface the name of the interface where the eth frame
 * 		encapsulating the ip datagram is to be sent
 * @param len the size of the ip datagram in bytes
 */
void bufferIPDatagram(struct sr_instance* sr, uint32_t ip, uint8_t * ip_datagram, char* interface, unsigned int len);
