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

int analyze_ICMP(u_char *data,int size);
int analyze_Packet(u_char *data,int size);
int analyze_ARP(u_char *data,int size);


int print_EtherHeader(struct ether_header *eh,FILE *fp);
char *MACaddress_int_to_str(u_char *hwaddr,char *buf,socklen_t size);
char *IP_address_int_to_IP_address_str(u_int32_t ip,char *buff,socklen_t size);
int print_ARP(struct ether_arp *arp,FILE *fp);
int print_ICMP(struct icmp *icmp,FILE *fp);
int print_IP_header(struct iphdr *iphdr,FILE *fp);

int main(int argc, char const *argv[]){

    const u_char *pkt;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char buff[5012];
    int size;

	pcap_t *handle = pcap_open_offline_with_tstamp_precision(argv[1],PCAP_TSTAMP_PRECISION_NANO, errbuf);

	if (handle == NULL) {
    	fprintf(stderr, "pcap_open: error %s\n", errbuf);
    	return (-1);
	}

	struct pcap_pkthdr pkthdr;

	int count=0;

	while((pkt = pcap_next(handle, &pkthdr))){
			printf("\n\n");
			
			count++;
			printf( "%d\n", count);
			printf("packet length: %d byte\n", pkthdr.caplen);
			print_EtherHeader((struct ether_header *)pkt,stdout);
			analyze_Packet(pkt,pkthdr.caplen);
		
	}
	pcap_close(handle);
}

int analyze_Packet(u_char *data,int size){
	
	u_char *ptr;
	int lest;

	struct ether_header *eh;

	ptr=data;
	lest=size;


	if(lest<sizeof(struct ether_header)){
		fprintf(stderr, "lest(%d)<sizeof(struct ether_header)\n",lest );
		return(-1);

	}

	eh=(struct ether_header *)ptr;
	ptr+=sizeof(struct ether_header);
	lest-=sizeof(struct ether_header);




	if(ntohs(eh->ether_type)==ETHERTYPE_IP){
		//analyze IP
		analyze_IP(ptr,lest);
	}

	return 0;


}


int analyze_IP(u_char *data,int size){

	u_char *ptr;
	int lest;

	struct iphdr *iphdr;

	u_char *option;
	int oplen;
	int len;
	unsigned short sum;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct iphdr)){
		fprintf(stderr, "error\n");
		return (-1);
	}
	
	iphdr=(struct iphdr*)ptr;
	ptr+=sizeof(struct iphdr);
	lest-=sizeof(struct iphdr);


	oplen=iphdr->ihl*4-sizeof(struct iphdr);

	fprintf(stderr, "IP option length:%d\n", oplen);

	if(oplen>0){
		if(oplen>=1500){
			fprintf(stderr, "IP oplen:%d\n",oplen);
			return (-1);
		}

		option=ptr;
		ptr+=oplen;
		lest-=oplen;

	}

	print_IP_header(iphdr,stdout);


	if(iphdr->protocol==IPPROTO_ICMP){
		analyze_ICMP(ptr,lest);
	}

	return 0;
		
}



int print_EtherHeader(struct ether_header *eh,FILE *fp)
{
    char buf[80];
    fprintf(fp,"===============ether header info=================\n");

    fprintf(fp,"ether_distination_host=%s\n",MACaddress_int_to_str(eh->ether_dhost,buf,sizeof(buf)));
    fprintf(fp,"ether_source_host=%s\n",MACaddress_int_to_str(eh->ether_shost,buf,sizeof(buf)));

    fprintf(fp,"ether_type=%02X",ntohs(eh->ether_type));
    switch(ntohs(eh->ether_type)){
        case	ETH_P_IP:
            fprintf(fp,"(IP)\n");
            break;
        case	ETH_P_IPV6:
            fprintf(fp,"(IPv6)\n");
            break;
        case	ETH_P_ARP:
            fprintf(fp,"(ARP)\n");
            break;
        default:
            fprintf(fp,"(unknown)\n");
            break;
    }
        fprintf(fp,"===============ether header info end=================\n");


    return(0);
}

int print_IP_header(struct iphdr *iphdr,FILE *fp){
    fprintf(fp, "============IP info=======================\n");

    char buff[2048];
    static char *protocol[]={

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

    fprintf(fp, "version:%u\n", iphdr->version);
    fprintf(fp, "header length:%u\n",iphdr->ihl);
    fprintf(fp, "type of service:%x\n",iphdr->tos);
    fprintf(fp, "packet total size:%u\n",ntohs(iphdr->tot_len));
    fprintf(fp, "protocol:%u ",iphdr->protocol);

    if((iphdr->protocol)<=25){
        fprintf(fp, "%s\n",protocol[iphdr->protocol]);
    }else{
        fprintf(fp, "undifined\n");
    }

    fprintf(fp, "Source IP:%s\n", IP_address_int_to_IP_address_str(iphdr->saddr,buff,sizeof(buff)));
    fprintf(fp, "target IP:%s\n", IP_address_int_to_IP_address_str(iphdr->daddr,buff,sizeof(buff)));

    fprintf(fp, "============IP info end=======================\n");

}

int analyze_ICMP(u_char *data,int size){
	
	u_char *ptr;
	int lest;

	ptr=data;
	lest=size;
	fprintf(stderr, "lest:%d\n", lest);


	struct icmp *icmp;

	icmp=(struct icmp *)ptr;
	ptr+=sizeof(struct icmp);

	lest-=sizeof(struct icmp);

	print_ICMP(icmp,stdout);

	return 0;
}
int print_ICMP(struct icmp *icmp,FILE *fp){
	static char *icmp_type[]={

		"Echo Reply",//
        "undefined",
        "undifined",
        "Destination Unreachable",
        "Source Quench",
        "Redirect",
        "undifined",
        "undifined",
        "Echo Request",
        "Router Advertisement",
        "Router Solicitation",
        "Time Exceeded",
        "Parameter Proble",
        "Timestamp",
        "Timestamp Reply",
        "Information Request",
        "Information Reply",
        "Address Mask Request",
        "Address Mask Reply",
		
	};

	fprintf(fp, "===============ICMP info=================\n");
	fprintf(fp, "icmp type=%u:",icmp -> icmp_type);

	if(icmp->icmp_type<=18){
		fprintf(fp, "%s\n",icmp_type[icmp->icmp_type]);
	}else{
		fprintf(fp, "undifined\n");
	}

	fprintf(fp, "icmp code=%u\n",icmp->icmp_code);
	fprintf(fp, "icmp check sum:%u\n",ntohs(icmp->icmp_cksum));

	if(icmp->icmp_type==0||icmp->icmp_type==8){
		fprintf(fp, "icmp id:%u\n",ntohs(icmp->icmp_id));
		fprintf(fp, "icmp sequence:%u\n",ntohs(icmp->icmp_seq));
	}
    fprintf(fp, "===============ICMP info end=================\n");
   
}


char *MACaddress_int_to_str(u_char *hwaddr,char *buff,socklen_t size){
	snprintf(buff,size,"%02x:%02x:%02x:%02x:%02x:%02x",
		hwaddr[0],hwaddr[1],hwaddr[2],hwaddr[3],hwaddr[4],hwaddr[5]);
	return(buff);
}

char *IP_address_int_to_IP_address_str(u_int32_t ip,char *buff,socklen_t size){
	struct in_addr *addr;
	addr=(struct in_addr *)&ip;
	inet_ntop(AF_INET,addr,buff,size);

	return(buff);

}





