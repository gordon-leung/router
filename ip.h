#include "sr_router.h"

int ip_dec_ttl(struct sr_instance* sr, uint8_t * ethPacket, unsigned int len, char* interface);

int ip_hdr_check(struct sr_instance* sr, uint8_t * ethPacket, unsigned int len, char* interface);
