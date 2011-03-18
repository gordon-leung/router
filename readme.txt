Group Members:

Holman Lan	 (hlan)
Gordon Leung (gal3)

Work Division:

ETHERNET
-Frame encapsulation									-Holman

ARP
-ARP reply    												-Gordon
-ARP request  												-Holman
-ARP cache														-Holman

IP
-Queueing IP datagrams								-Holman
-Forwarding via longest prefix match	-Holman
-Decrement TTL/Recalculate checksum 	-Gordon
-Check for valid IP datagrams					-Gordon

ICMP
-Echo reply														-Gordon
-Timeout															-Gordon
-Port Unreachable											-Gordon
-Host unreachable											-Gordon
-Calculate checksum										-Gordon
-Placing where to send ICMP messages  -Holman

Known Bugs/Issues: None.

Code Design: We separated functionality of each layer into it's own file.

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
