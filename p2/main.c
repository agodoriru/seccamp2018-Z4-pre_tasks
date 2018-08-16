#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arcnet.h>
#include <linux/version.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>

int analyze_ICMP(u_char * data, int size);
bool analyze_Packet(const u_char * data, bpf_u_int32 size);
int analyze_ARP(u_char * data, int size);

int print_EtherHeader(struct ether_header *eh, FILE * fp);
char *MACaddress_int_to_str(const uint8_t * hwaddr, char *buf, size_t size);
char *IP_address_int_to_IP_address_str(u_int32_t ip, char *buff,
				       socklen_t size);
int print_ARP(struct ether_arp *arp, FILE * fp);
int print_ICMP(struct icmp *icmp, FILE * fp1, u_char * option, int lest,
	       FILE * fp2);
// int print_IP_header(struct iphdr *iphdr,FILE *fp);
int analyze_IP(u_char * data, int size);

int print_tcp(struct tcphdr *tcphdr, FILE * fp);
int analyze_TCP(u_char * data, int size);

char *get_dest_ip(const struct iphdr *iphdr);
char *get_src_ip(const struct iphdr *iphdr);

char *get_ip_protocol(const struct iphdr *iphdr);

int input_filter_info(void);
void output_filter_info(void);
bool check_packet(const struct iphdr *iphdr, const void *l4hdr);

void write_filehdr(FILE *fp);
void write_packet(FILE *fp, const void *pkt, uint32_t len);
// in sample program ////////////////////////////////

struct pcap_file_hdr {
	uint32_t magic_number;	/* magic number */
	uint16_t version_major;	/* major version number */
	uint16_t version_minor;	/* minor version number */
	int32_t thiszone;	/* GMT to local correction */
	uint32_t sigfigs;	/* accuracy of timestamps */
	uint32_t snaplen;	/* max length of captured packets, in octets */
	uint32_t network;	/* data link type */
};

struct pcap_pkt_hdr {
	uint32_t ts_sec;	/* timestamp seconds */
	uint32_t ts_usec;	/* timestamp microseconds */
	uint32_t incl_len;	/* number of octets of packet saved in file */
	uint32_t orig_len;	/* actual length of packet */
};

void write_filehdr(FILE * fp)
{
	struct pcap_file_hdr fh;
	fh.magic_number = 0xa1b2c3d4;
	fh.version_major = 2;
	fh.version_minor = 4;
	fh.thiszone = 0;
	fh.sigfigs = 0;
	fh.snaplen = 65535;
	fh.network = 1;
	fwrite(&fh, sizeof(fh), 1, fp);
}

void write_packet(FILE * fp, const void *pkt, uint32_t len)
{
	struct pcap_pkt_hdr ph;
	ph.ts_sec = 0;
	ph.ts_usec = 0;
	ph.incl_len = len;
	ph.orig_len = len;
	fwrite(&ph, sizeof(ph), 1, fp);
	fwrite(pkt, len, 1, fp);
}

////////////////////////////////////////////////////

static uint32_t filter_source_ip;
static uint32_t filter_dest_ip;
static uint16_t filter_dest_port;
static uint16_t filter_source_port;
static uint8_t  filter_protocol;

static char buff_1[65535];
static char buff_2[65535];

static int match = 0;

static FILE *logfile;

int main(int argc __attribute__((unused)), char const *argv[])
{
	const u_char *pkt;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr pkthdr;

	if (argv[1] == NULL) {
		fprintf(stdout, "input data\n");
		return (-1);
	}

	logfile = fopen("output.log", "w");
	if (logfile == NULL) {
		fprintf(stderr, "err cant open file");
		return (-1);
	}
	while(1){
		int res = input_filter_info();
		if (res == 0)
			break;
	}
	// output_filter_info();
	// exit(0)

	pcap_t *handle =
	    pcap_open_offline_with_tstamp_precision(argv[1],
						    PCAP_TSTAMP_PRECISION_NANO,
						    errbuf);
	if (handle == NULL) {
		fprintf(stderr, "pcap_open: error %s\n", errbuf);
		return (-1);
	}

	int count = 0;

	FILE *fp = fopen("output.pcap", "wb");
	write_filehdr(fp);
	output_filter_info();
	
	while ((pkt = pcap_next(handle, &pkthdr))) {
		count++;
		// fprintf(logfile, "==========================================================\n\n");
		fprintf(logfile,"\nNo.%d\n", count);
		// fprintf(logfile,"packet length : %d byte\n\n", pkthdr.caplen);
		if (analyze_Packet(pkt, pkthdr.caplen) == true) {
			match++;
			write_packet(fp, pkt, pkthdr.caplen);
		}
	}
	pcap_close(handle);
	printf("match:%d\n", match);
	printf("count:%d\n", count);
	fclose(logfile);
	return 0;
}

bool analyze_Packet(const u_char * data, bpf_u_int32 size)
{
	const u_char *ptr;
	bpf_u_int32 lest;
	const struct ether_header *eh;
	const struct iphdr *iphdr;
	const u_char *option;
	unsigned int oplen;

	ptr = data;
	lest = size;

	if (lest < sizeof(struct ether_header)) {
		fprintf(stderr, "lest(%d)<sizeof(struct ether_header)\n", lest);
		return false;
	}

	eh = (const struct ether_header *)ptr;
	ptr += sizeof(struct ether_header);
	lest -= sizeof(struct ether_header);

	uint16_t ether_type=ntohs(eh->ether_type);

	char buf[80];
	fprintf(logfile,"==== ether info ====\n");
	fprintf(logfile,"ether dest host:%s\n",MACaddress_int_to_str(eh->ether_dhost,buf,sizeof(buf)));
	fprintf(logfile,"ether src  host:%s\n",MACaddress_int_to_str(eh->ether_shost,buf,sizeof(buf)));
	fprintf(logfile,"ether type:0x%02X ",ether_type);

	switch(ether_type){
		case ETHERTYPE_IP:
			fprintf(logfile, "[IP]\n");
			break;
		case ETHERTYPE_ARP:
			fprintf(logfile, "[ARP]\n");
			return false;
		default:
			fprintf(logfile,"\n");
			return false;
	}

	// fprintf(logfile, "analyze ip\n");

	if (lest < sizeof(struct iphdr)) {
		fprintf(stderr, "error\n");
		return false;
	}

	iphdr = (const struct iphdr *)ptr;
	ptr += sizeof(struct iphdr);
	lest -= sizeof(struct iphdr);

	oplen = iphdr->ihl * 4 - sizeof(struct iphdr);

	fprintf(logfile, "==== IP info ====\n");
	fprintf(logfile, "src ip:%s\n", get_src_ip(iphdr));
	fprintf(logfile, "dest ip:%s\n", get_dest_ip(iphdr));
	fprintf(logfile, "ip protocol:%s\n", get_ip_protocol(iphdr));
	fprintf(logfile, "oplen:%u\n", oplen);

	if (oplen > 0) {
		if (oplen >= 1500) {
			fprintf(stderr, "IP option length:%d\n", oplen);
			return false;
		}

		option = ptr;
		ptr += oplen;
		lest -= oplen;
		// IP option (variable length)
	}

	if (iphdr->protocol == IPPROTO_TCP) {
		const struct tcphdr *tcphdr = (const struct tcphdr *)ptr;

		fprintf(logfile, "==== TCP info ====\n");
		fprintf(logfile, "src port:%u\n", ntohs(tcphdr->source));
		fprintf(logfile, "dest port:%u\n", ntohs(tcphdr->dest));
		fprintf(logfile, "seq:%u\n", ntohl(tcphdr->seq));
		fprintf(logfile, "ack:%u\n", ntohl(tcphdr->ack_seq));

		bool res =
		    check_packet(iphdr, (const void*)tcphdr);

		fprintf(logfile, "result:%d\n", res);

		return res;
	} else if (iphdr->protocol == IPPROTO_UDP) {
		const struct udphdr *udphdr = (const struct udphdr *)ptr;

		fprintf(logfile, "==== UDP info ====\n");
		fprintf(logfile, "src port:%u\n", ntohs(udphdr->source));
		fprintf(logfile, "dest port:%u\n", ntohs(udphdr->dest));

		return false;
	}
	return false;

}

char *get_ip_protocol(const struct iphdr *iphdr)
{
	static char *protocol[] = {
		"undifined",
		"ICMP",
		"IGMP",
		"undifined",
		"IP",
		"undifined",
		"TCP",
		"CBT",
		"EGP",
		"IGP",
		"undifined",
		"undifined",
		"undifined",
		"undifined",
		"undifined",
		"undifined",
		"undifined",
		"UDP",
	};

	// fprintf(logfile, "protocol : %u ",iphdr->protocol);

	if ((iphdr->protocol) <= 17) {
		return protocol[iphdr->protocol];
	} else {
		return "undifined";
	}
}

char *get_dest_ip(const struct iphdr *iphdr)
{
	return (IP_address_int_to_IP_address_str
		(iphdr->daddr, buff_1, sizeof(buff_1)));
}

char *get_src_ip(const struct iphdr *iphdr)
{
	return (IP_address_int_to_IP_address_str
		(iphdr->saddr, buff_2, sizeof(buff_2)));
}

char *IP_address_int_to_IP_address_str(u_int32_t ip, char *buff, socklen_t size)
{
	struct in_addr *addr;
	addr = (struct in_addr *)&ip;
	inet_ntop(AF_INET, addr, buff, size);
	return (buff);
}

char *MACaddress_int_to_str(const uint8_t * hwaddr, char *buff, size_t size)
{
	snprintf(buff, size, "%02x:%02x:%02x:%02x:%02x:%02x",
		 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4],
		 hwaddr[5]);
	return (buff);
}

int input_filter_info(void)
{
	unsigned long int dest_port_ul;
	unsigned long int src_port_ul;
	char dest_port_str[256];
	char src_port_str[256];
	char dest_ip[256];
	char src_ip[256];
	char protocol[256];
	int res;

	printf("input filter dest ip:");
	errno = 0;
	res = scanf("%s", dest_ip);
	if(errno != 0) {
		perror("scanf");
		return -1;
	}else if(res != 1) {
		fprintf(stderr,"scanf failed\n");
		return -1;
	}
	filter_dest_ip = inet_addr(dest_ip);
	if(filter_dest_ip == INADDR_NONE){
		fprintf(stderr,"invalid address\n");
		return -1;
	}

	printf("input filter source ip:");
	errno = 0;
	res = scanf("%s", src_ip);
	if(errno != 0) {
		perror("scanf");
		return -1;
	}else if(res != 1) {
		fprintf(stderr,"scanf failed\n");
	}
	filter_source_ip = inet_addr(src_ip);
	if(filter_source_ip==INADDR_NONE) {
		fprintf(stderr,"invalid address\n");
		return -1;
	}

	printf("input filter protocol:");
	errno = 0;
	res = scanf("%s", protocol);
	if(errno != 0) {
		perror("scanf");
		return -1;
	}else if(res != 1) {
		fprintf(stderr,"scanf failed\n");
		return -1;
	}
	if(strcmp(protocol, "TCP") == 0){
		filter_protocol = IPPROTO_TCP;
	}else if (strcmp(protocol, "UDP") == 0){
		filter_protocol = IPPROTO_UDP;
	}else{
		fprintf(stderr,"invalid protocol\n");
		return -1;
	}

	printf("input filter dest port:");
	errno = 0;
	res = scanf("%s", dest_port_str);
	if(errno != 0) {
		perror("scanf");
		return -1;
	}else if(res != 1) {
		fprintf(stderr,"scanf failed\n");
		return -1;
	}

	errno = 0;
	dest_port_ul = strtoul(dest_port_str, NULL, 10);
	if(errno != 0) {
		perror("strtoul");
		return -1;
	} else if(dest_port_ul > UINT16_MAX) {
		fprintf(stderr, "port number too large\n");
		return -1;
	} else if(dest_port_ul == 0) {
		fprintf(stderr, "invalid port number\n");
		return -1;
	}
	filter_dest_port = htons((uint16_t)dest_port_ul);

	printf("input filter source port:");
	errno = 0;
	res = scanf("%s", src_port_str);

	if(errno != 0) {
		perror("scanf");
		return -1;
	}else if(res != 1) {
		fprintf(stderr,"scanf failed\n");
		return -1;
	}

	errno = 0;
	src_port_ul = strtoul(src_port_str, NULL, 10);
	if(errno != 0) {
		perror("strtoul");
		return -1;
	} else if(src_port_ul > UINT16_MAX) {
		fprintf(stderr, "port number too large\n");
		return -1;
	} else if(src_port_ul == 0) {
		fprintf(stderr, "invalid port number\n");
		return -1;
	}
	filter_source_port = htons((uint16_t)src_port_ul);

	return 0;

}

void output_filter_info(void)
{
	struct in_addr source = { filter_source_ip };
	struct in_addr dest   = { filter_dest_ip };

	fprintf(logfile,
		" ======================= filter info =======================\n");
	fprintf(logfile, " * filter_dest_ip:%s\n", inet_ntoa(dest));
	fprintf(logfile, " * filter_source_ip:%s\n", inet_ntoa(source));
	fprintf(logfile, " * filter_protocol:%hhu\n", filter_protocol);
	fprintf(logfile, " * filter_dest_port:%u\n", ntohs(filter_dest_port));
	fprintf(logfile, " * filter_source_port:%u\n", ntohs(filter_source_port));
	fprintf(logfile,
		" ============================================================\n");
	// exit(0);
}

bool check_packet(const struct iphdr *iphdr, const void *l4hdr)
{
	//const char *any = "any";
	int chech_packet_arr[5] = { 0 };
	int check_count = 0;
	const struct tcphdr *tcphdr = (const struct tcphdr *)l4hdr;

	//struct in_addr source = { filter_source_ip };
	//struct in_addr dest   = { filter_dest_ip };
	//struct in_addr source_in_ip = {iphdr->saddr};
	//struct in_addr dest_in_ip = {iphdr->daddr};

	//fprintf(logfile, "in check packet func \n" );
	//fprintf(logfile, "src ip          :%s\n",inet_ntoa(source_in_ip) );
	//fprintf(logfile, "filter source ip:%s\n",inet_ntoa(source) );
	//fprintf(logfile, "dest ip         :%s\n",inet_ntoa(dest_in_ip) );
	//fprintf(logfile, "filter dest ip  :%s\n",inet_ntoa(dest) );


	if (iphdr->saddr == filter_source_ip ) {
		//fprintf(logfile, "source IP  :   bingo\n");
		chech_packet_arr[0] = 1;
	} else {
		// fprintf(logfile, "source IP:miss\n" );
	}

	if (iphdr->daddr == filter_dest_ip ) {
		//fprintf(logfile, "destination IP:bingo\n");
		chech_packet_arr[1] = 1;
	} else {
		// fprintf(logfile, "destination IP:miss\n" );
	}

	if (iphdr->protocol==filter_protocol) {
		//fprintf(logfile, "ip  protocol : bingo\n");
		chech_packet_arr[2] = 1;
	} else {
		// fprintf(logfile, "IP protocol:miss\n" );
	}


	if (tcphdr->source==filter_source_port) {
		//fprintf(logfile, "source  port : bingo\n");
		chech_packet_arr[3] = 1;
	} else {
		// fprintf(logfile, "source port:miss\n" );
	}

	if (tcphdr->dest==filter_dest_port) {
		//fprintf(logfile, "dest  port  :  bingo\n");
		chech_packet_arr[4] = 1;
	} else {
		// fprintf(logfile, "destination port:miss\n" );
	}

	int i;
	for (i = 0; i < 5; i++) {
		if (chech_packet_arr[i] == 1) {
			check_count++;
		}
	}
	if (check_count == 5) {
		return 1;
	} else {
		return 0;
	}
}
