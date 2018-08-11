#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


int main(int argc, char const *argv[]){
	
	u_char *pkt;
	char errbuf[PCAP_ERRBUF_SIZE];
	

	if(argv[1]==NULL){
		fprintf(stderr, "error\n");
	}

	pcap_t *handle = pcap_open_offline_with_tstamp_precision(argv[1],PCAP_TSTAMP_PRECISION_NANO, errbuf);

	

	return 0;
}