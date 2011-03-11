#include "sr_router.h"

int icmp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);

uint8_t* create_icmp(struct sr_instance* sr, uint8_t * ip_datagram, int type, int code);

void ipDatagramTimeExceeded(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len);

void destinationUnreachable(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len, unsigned short code);

void parameterProblem(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len, unsigned short code, uint8_t pointer);

void handleIcmpMessageReceived(struct sr_instance* sr, uint8_t * ip_datagram, unsigned int ip_datagram_len);

