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

int analyze_ICMP(u_char * data, int size);
int analyze_Packet(const u_char * data, bpf_u_int32 size);
int analyze_ARP(u_char * data, int size);

int print_EtherHeader(struct ether_header *eh, FILE * fp);
char *MACaddress_int_to_str(u_char * hwaddr, char *buf, socklen_t size);
char *IP_address_int_to_IP_address_str(u_int32_t ip, char *buff,
				       socklen_t size);
int print_ARP(struct ether_arp *arp, FILE * fp);
int print_ICMP(struct icmp *icmp, FILE * fp1, u_char * option, int lest,
	       FILE * fp2);
// int print_IP_header(struct iphdr *iphdr,FILE *fp);
int analyze_IP(u_char * data, int size);

int print_tcp(struct tcphdr *tcphdr, FILE * fp);
int analyze_TCP(u_char * data, int size);

uint16_t get_tcp_src_port(const u_char * data);
uint16_t get_tcp_dest_port(const u_char * data);
//int get_udp_dest_port(const u_char *data);
//int get_udp_src_port(const u_char *data);

char *get_dest_ip(struct iphdr *iphdr);
char *get_src_ip(struct iphdr *iphdr);

char *get_ip_protocol(struct iphdr *iphdr);

void input_filter_info(void);
void output_filter_info(void);
int check_packet(const char *src_ip, const char *dest_ip, const char *proto,
		 uint16_t src_port, uint16_t dest_port);

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

static char filter_dest_ip[256];
static char filter_source_ip[256];
static char filter_protocol[256];
static char filter_dest_port[256];
static char filter_source_port[256];

static char buff_2[65535];
static char buff_1[65535];

static int counter = 0;

static FILE *logfile;

int main(int argc, char const *argv[])
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
	input_filter_info();
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

	while ((pkt = pcap_next(handle, &pkthdr))) {
		count++;
		// fprintf(logfile, "==========================================================\n\n");
		// fprintf(logfile,"No.%d\n", count);
		// fprintf(logfile,"packet length : %d byte\n\n", pkthdr.caplen);
		if (analyze_Packet(pkt, pkthdr.caplen) == 1) {
			counter++;
			write_packet(fp, pkt, pkthdr.caplen);
		}
	}
	pcap_close(handle);
	printf("match:%d\n", counter);
	fclose(logfile);
	return 0;
}

int analyze_Packet(const u_char * data, bpf_u_int32 size)
{
	const u_char *ptr;
	bpf_u_int32 lest;
	struct ether_header *eh;
	struct iphdr *iphdr;
	const u_char *option;
	int oplen;

	ptr = data;
	lest = size;

	if (lest < sizeof(struct ether_header)) {
		fprintf(stderr, "lest(%d)<sizeof(struct ether_header)\n", lest);
		return (-1);
	}

	eh = (struct ether_header *)ptr;
	ptr += sizeof(struct ether_header);
	lest -= sizeof(struct ether_header);

	if (ntohs(eh->ether_type) != ETHERTYPE_IP) {
		// fprintf(logfile, "analyzing ip\n" );
		// analyze_IP(ptr,lest);

	}
	// fprintf(logfile, "analyze ip\n");

	if (lest < sizeof(struct iphdr)) {
		fprintf(stderr, "error\n");
		return (-1);
	}

	iphdr = (struct iphdr *)ptr;
	ptr += sizeof(struct iphdr);
	lest -= sizeof(struct iphdr);

	oplen = iphdr->ihl * 4 - sizeof(struct iphdr);

	if (oplen > 0) {
		if (oplen >= 1500) {
			fprintf(stderr, "IP option length:%d\n", oplen);
			return (-1);
		}

		option = ptr;
		ptr += oplen;
		lest -= oplen;
		// IP option (variable length)
	}

	if (iphdr->protocol == IPPROTO_TCP) {
		output_filter_info();
		fprintf(logfile, "==== IP info ====\n");
		fprintf(logfile, "src ip:%s\n", get_src_ip(iphdr));
		fprintf(logfile, "dest ip:%s\n", get_dest_ip(iphdr));
		fprintf(logfile, "ip protocol:%s\n", get_ip_protocol(iphdr));
		fprintf(logfile, "==== port info ====\n");
		fprintf(logfile, "src port:%u\n", get_tcp_src_port(ptr));
		fprintf(logfile, "dest port:%u\n", get_tcp_dest_port(ptr));
		fprintf(logfile, "\n");
		fprintf(logfile, "dest ip:%s\n", get_dest_ip(iphdr));

		int res =
		    check_packet(get_src_ip(iphdr), get_dest_ip(iphdr),
				 get_ip_protocol(iphdr),
				 get_tcp_src_port(ptr), get_tcp_dest_port(ptr));

		fprintf(logfile, "result:%d\n", res);

		return res;

	} else if (iphdr->protocol == IPPROTO_UDP) {
		//int packet_dest_port=get_udp_dest_port(ptr);
		//int packet_src_port=get_udp_dest_port(ptr);
	}

	return 0;

}

uint16_t get_tcp_src_port(const u_char * data)
{
	const u_char *ptr;
	struct tcphdr *tcphdr;
	ptr = data;
	tcphdr = (struct tcphdr *)ptr;
	return ntohs(tcphdr->source);
}

uint16_t get_tcp_dest_port(const u_char * data)
{
	const u_char *ptr;
	struct tcphdr *tcphdr;
	ptr = data;
	tcphdr = (struct tcphdr *)ptr;
	return ntohs(tcphdr->dest);
}

/*
int get_udp_dest_port(const u_char *data){
	const u_char *ptr;
	struct udphdr *udphdr;
	ptr=data;
	udphdr=(struct udphdr *)ptr;
	return ntohs(udphdr->dest);
}

int get_udp_src_port(const u_char *data){
	const u_char *ptr;
	struct udphdr *udphdr;
	ptr=data;
	udphdr=(struct udphdr *)ptr;
	return ntohs(udphdr->source);

}
*/

char *get_ip_protocol(struct iphdr *iphdr)
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

char *get_dest_ip(struct iphdr *iphdr)
{
	return (IP_address_int_to_IP_address_str
		(iphdr->daddr, buff_1, sizeof(buff_1)));
}

char *get_src_ip(struct iphdr *iphdr)
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

char *MACaddress_int_to_str(u_char * hwaddr, char *buff, socklen_t size)
{
	snprintf(buff, size, "%02x:%02x:%02x:%02x:%02x:%02x",
		 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4],
		 hwaddr[5]);
	return (buff);
}

void input_filter_info(void)
{
	printf("input filter dest ip:");
	scanf("%s", filter_dest_ip);
	printf("input filter source ip:");
	scanf("%s", filter_source_ip);
	printf("input filter protocol:");
	scanf("%s", filter_protocol);
	printf("input filter dest port:");
	scanf("%s", filter_dest_port);
	printf("input filter source port:");
	scanf("%s", filter_source_port);
}

void output_filter_info(void)
{
	fprintf(logfile,
		" ======================= filter info =======================\n");
	fprintf(logfile, " * filter_dest_ip:%s\n", filter_dest_ip);
	fprintf(logfile, " * filter_source_ip:%s\n", filter_source_ip);
	fprintf(logfile, " * filter_protocol:%s\n", filter_protocol);
	fprintf(logfile, " * filter_dest_port:%s\n", filter_dest_port);
	fprintf(logfile, " * filter_source_port:%s\n", filter_source_port);
	fprintf(logfile,
		" ============================================================\n");
	// exit(0);
}

int check_packet(const char *src_ip, const char *dest_ip, const char *proto,
		 uint16_t src_port, uint16_t dest_port)
{
	const char *any = "any";
	int chech_packet_arr[5] = { 0 };
	int check_count = 0;

	// fprintf(logfile, "in check packet func \n" );
	// fprintf(logfile, "src ip          :%s\n",src_ip );
	// fprintf(logfile, "filter source ip:%s\n",filter_source_ip );
	// fprintf(logfile, "dest ip         :%s\n",dest_ip );
	// fprintf(logfile, "filter dest ip  :%s\n",filter_dest_ip );

	if (strcmp(src_ip, filter_source_ip) == 0
	    || strcmp(filter_source_ip, any) == 0) {
		// fprintf(logfile, "source IP:bingo\n");
		chech_packet_arr[1] = 1;
	} else {
		// fprintf(logfile, "source IP:miss\n" );
	}

	if (strcmp(dest_ip, filter_dest_ip) == 0
	    || strcmp(filter_dest_ip, any) == 0) {
		// fprintf(logfile, "destination IP:bingo\n");
		chech_packet_arr[0] = 1;
	} else {
		// fprintf(logfile, "destination IP:miss\n" );
	}

	if (strcmp(proto, filter_protocol) == 0
	    || strcmp(filter_protocol, any) == 0) {
		// fprintf(logfile, "ip protocol:bingo\n");
		chech_packet_arr[2] = 1;
	} else {
		// fprintf(logfile, "IP protocol:miss\n" );
	}

	char get_tcp_dest_port_str[256];
	char get_tcp_src_port_str[256];

	snprintf(get_tcp_dest_port_str, 256, "%u", dest_port);
	snprintf(get_tcp_src_port_str, 256, "%u", src_port);

	// fprintf(logfile, "%s\n", get_tcp_dest_port_str);
	// fprintf(logfile, "%s\n", get_tcp_src_port_str);

	if (strcmp(get_tcp_src_port_str, filter_source_port) == 0
	    || strcmp(filter_source_port, any) == 0) {
		// fprintf(logfile, "source port:bingo\n");
		chech_packet_arr[4] = 1;
	} else {
		// fprintf(logfile, "source port:miss\n" );
	}

	if (strcmp(get_tcp_dest_port_str, filter_dest_port) == 0
	    || strcmp(filter_dest_port, any) == 0) {
		// fprintf(logfile, "destination port:bingo\n");
		chech_packet_arr[3] = 1;
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
