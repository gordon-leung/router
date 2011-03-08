/*
 * Ethernet.h
 *
 *  Created on: 2011-03-06
 *      Author: holman
 */
#include "sr_router.h"

#define BROAD_CAST_MAC 255

/*Handle the eth packet received.*/
void handleEthPacket(struct sr_instance* sr,
        uint8_t * ethPacket,
        unsigned int len,
        char* interface);

/*Prints the mac address to stdout in hex with
 * format xx-xx-xx-xx-xx-xx
 */
void printEthAddr(uint8_t* eth_hdr);

/*Check the mac address passed to see if it is a broadcast address
 * @return 1 if it is broad cast address, return 0 otherwise
 *
 */
int isBroadCastMAC(const uint8_t* macAddr);

/*Compare two mac address to see if they are the same.
 * @return: 1 if they are the same, return 0 otherwise.
 */
int MACcmp(const uint8_t* macAddr1, const uint8_t* macAddr2);
