#include "check.h"

//One's complement checksum for "count" bytes beginning at location "addr"
//As defined in RFC 1071

int csum(const uint16_t *addr, int count){
	int sum = 0;
	uint16_t checksum = 0;

	while( count > 1 )  {
	//Add 16 bits at a time
		sum += (*(unsigned short *)(addr++));
		count -= 2;
	}

  //Add 8 bits more if odd number of bytes specified
	if( count > 0 ){
		sum += *(unsigned char *) addr;
	}

  //Add overflow if any
	while (sum>>16){
		sum = (sum & 0xffff) + (sum >> 16);
	}
	checksum = ~sum;
	return checksum;
}
