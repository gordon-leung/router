Group Members:

Holman Lan	 (hlan)
Gordon Leung (gal3)

Work Division:

ETHERNET
-Encapsulating ip datagram and arp messages into ethernet frame		-Holman
-Ethernet layer demultiplexing						-Holman

ARP
-ARP reply    								-Gordon
-ARP request  								-Holman
-ARP table								-Holman
-ARP request tracking							-Holman

IP
-IP layer demultiplexing						-Holman
-IP datagrams buffering							-Holman
-Forwarding via longest prefix match					-Holman
-Encapsulating icmp messages into ip datagram				-Holman
-Decrement TTL/Recalculate checksum 					-Gordon
-Check for valid IP datagrams						-Gordon

ICMP
-Echo reply								-Gordon
-Time exceeded								-Gordon
-Port Unreachable							-Gordon
-Host unreachable							-Gordon
-Calculate checksum							-Gordon

Known Bugs/Issues: None.

Code Design: 
The router is organized into three logical layers: ethernet, ip, and icmp. 

The ethernet layer: is the bottom layer of this architecture and provids services to the ip layer to encapsulate ip datagram and arp message into an ethernet frame. It is also the only point of interaction with the stub code for sending and receiving ethernet frames. The source code file that make up this layer are: Ethernet.c Ethernet.h

The ip layer: consists of arp, demultiplexing and forwarding, checksum, and ip datagram buffering components. The ip layer also provide services to the icmp layer to encapsulate icmp message into an ip datagram. 
	-The arp component is responsible for handling arp requests, constructing arp request and response, maintaining arp table, tracking arp requests sent, resolving ip-mac from arp table, and resolving ip-mac using arp requests. The arp table is implemented using a doubly-linked list of arp table entry. There is one arp table associated with each interface of the router. For each ip-mac resolution requiring an arp request to be sent, there is a tracker keeping track of the number of arp requests that have been sent for this resolution and the time of the last arp request sent. The tackers are organized in a doubly-linked list. Source files associated with this component are: ARP.c ARP.h
	-When an ip datagram is received, checksum and header fields need to be checked to determine if ip datagram should be processed or dropped, and if it is to be process, which componet it should be sent to, i.e. icmp or fordarding. The forwarding component uses the forwarding table to look up the next hop. The stub code implemetation of forwarding table is used, i.e. linked list. Source files associated to this component is ip.c ip.h check.c check.h
	-Ip datagram buffering buffers the ip datagram that are to be sent but are currently waiting for arp resolution with arp request. There is one buffer associate with each ip that need to be resolved. Each buffer made up of a singly-linked list of ip datagrams. Bufferes are stored as a doubly-linked list. Source files associated with this component are: IpDatagramBuffer.c IpDatagramBuffer.h

The icmp layer: handles icmp echo request and errors requiring icmp messages to be sent, as well as the construction of icmp message to carry the error message back to the sender of the problematic ip datagram. Source files associated with this layer are: icmp.c icmp.h


We separated functionality of each layer into it's own file.

Ethernet.c
-Demultiplexes ARP and IP messages
-Encapsulates packets into frames and sends it out

ARP.c
-Creates ARP reply/response and sends it to the Ethernet layer
-Adds ARP entries into the ARP cache
-Checks for inactive ARP entries and deletes them
-Data structure of ARP cache ???

ip.c
-Checks if IP datagram is valid, else drop it
-Checks to see if TTL > 1
-Do longest prefix matching for destination IP
-Decrements the TTL and recomputes the checksum then sends it to the Ethernet layer
-Sends out the appropriate ICMP messages
-Encapsulates ICMP messages and sends it to the Ethernet layer

IPDatagramBuffer.c
-???

icmp.c
-Creates ICMP messages and then passes it to the IP layer

check.c
-Computes one's complement checksum by adding 16 bit words plus any overflow, and returns the complement.

Defs.h
-Holds global constants

sr_protocol.h
-Defined the ICMP message structure
