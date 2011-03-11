#include "sr_router.h"

int icmp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);

uint8_t* create_icmp(struct sr_instance* sr, uint8_t * ip_datagram, int type, int code);
