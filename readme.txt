Group Members:

Holman Lan	 (hlan)
Gordon Leung (gal3)

Work Division:

ETHERNET
-Encapsulating ip datagram and arp messages into ethernet frame		-Holman
-Ethernet layer demultiplexing																		-Holman

ARP
-ARP reply    								-Gordon
-ARP request  								-Holman
-ARP table										-Holman
-ARP request tracking					-Holman

IP
-IP layer demultiplexing												-Holman
-IP datagrams buffering													-Holman
-Forwarding via longest prefix match						-Holman
-Encapsulating icmp messages into ip datagram		-Holman
-Decrement TTL/Recalculate checksum 						-Gordon
-Check for valid IP datagrams										-Gordon

ICMP
-Echo reply								-Gordon
-Time exceeded						-Gordon
-Port Unreachable					-Gordon
-Host unreachable					-Gordon
-Calculate checksum				-Gordon

Known Bugs/Issues: None.

Code Design: 
The router is organized into three logical layers: ethernet, ip, and icmp. 

The ethernet layer: is the bottom layer of this architecture and provides services to the ip layer to encapsulate ip datagram and arp message into an ethernet frame. It is also the only point of interaction with the stub code for sending and receiving ethernet frames.

Ethernet.c
-Demultiplexes ARP and IP messages
-Encapsulates packets into frames and sends it out

The ip layer: consists of arp, demultiplexing and forwarding, checksum, and ip datagram buffering components. The ip layer also provide services to the icmp layer to encapsulate icmp message into an ip datagram. 

There is one arp cache associated with each interface of the router. For each ip-mac resolution requiring an arp request to be sent, there is a tracker of the number of arp requests that have been sent for this resolution and the time of the last arp request sent. The trackers are organized in a doubly-linked list.

ARP.c
-Creates ARP reply/response and sends it to the Ethernet layer
-Adds ARP entries into the ARP cache
-Checks for inactive ARP entries and deletes them
-Tracks arp requests sent
-Resolves ip-mac using arp cache
-Data structure of ARP cache: doubly-linked list of arp entries

ip.c
-Check checksum and header fields of IP datagram for validity, else drop it
-Checks to see if TTL > 1
-Do longest prefix matching of destination IP to get next hop
-The stub code implemetation of forwarding table is used, i.e. linked list.
-Decrements the TTL and recomputes the checksum then sends it to the Ethernet layer
-Sends out the appropriate ICMP messages
-Encapsulates ICMP messages and sends it to the Ethernet layer

IPDatagramBuffer.c
-Buffers IP datagrams that are to be sent but are waiting for arp resolution with arp request. There is one buffer associated with each IP that needs to be resolved. Each buffer is made up of a singly-linked list of IP datagrams. Buffers are stored as a doubly-linked list.

icmp.c
-Creates ICMP messages and then passes it to the IP layer

check.c
-Computes one's complement checksum by adding 16 bit words plus any overflow, and returns the complement.

Defs.h
-Holds global constants

sr_protocol.h
-Defined the ICMP message structure
