/*
 * ARP.h
 *
 *  Created on: 2011-03-06
 *      Author: holman
 */

#include "sr_protocol.h"
#include "sr_if.h"

int handleArpPacket(struct sr_arphdr* arphdr, struct sr_if* iface);
