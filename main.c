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
int print_ICMP(struct icmp *icmp,FILE *fp1,u_char *option,int lest,FILE *fp2);
int print_IP_header(struct iphdr *iphdr,FILE *fp);
int analyze_IP(u_char *data,int size);


FILE *f_data;

struct icmp_hdr{
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint16_t iden;
    uint16_t seqnum;
};

int main(int argc, char const *argv[]){

    u_char *pkt;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr pkthdr;

    if(argv[1]==NULL){
    	fprintf(stdout, "input data\n");
    	return (-1);
    }

	pcap_t *handle = pcap_open_offline_with_tstamp_precision(argv[1],PCAP_TSTAMP_PRECISION_NANO, errbuf);

	if (handle == NULL) {
    	fprintf(stderr, "pcap_open: error %s\n", errbuf);
    	return (-1);
	}

	int count=0;

	f_data=fopen("png_get_daze.jpg","wb+");

	while((pkt = pcap_next(handle, &pkthdr))){
			printf("\n\n");
			
			count++;
			fprintf(stdout, "==========================================================\n");
			fprintf(stdout, "==========================================================\n");
			fprintf(stdout, "==========================================================\n\n");

			fprintf(stdout,"No.%d\n", count);
			fprintf(stdout,"packet length : %d byte\n\n", pkthdr.caplen);
			print_EtherHeader((struct ether_header *)pkt,stdout);
			analyze_Packet(pkt,pkthdr.caplen);
		
	}

	pcap_close(handle);
	fclose(f_data);

	return 0;
}

int analyze_Packet(u_char *data,int size){
	
	u_char *ptr;
	int lest;
	struct ether_header *eh;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct ether_header)){
		fprintf(stderr, "lest(%d)<sizeof(struct ether_header)\n",lest );
		return (-1);

	}

	eh=(struct ether_header *)ptr;
	ptr+=sizeof(struct ether_header);
	lest-=sizeof(struct ether_header);

	if(ntohs(eh->ether_type)==ETHERTYPE_IP){
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

	

	if(oplen>0){
		if(oplen>=1500){
			fprintf(stderr, "IP option length:%d\n", oplen);
			return (-1);
		}

		option=ptr;
		ptr+=oplen;
		lest-=oplen;
		// IP option (variable length)

	}

	print_IP_header(iphdr,stdout);

	if(iphdr->protocol==IPPROTO_ICMP){
		analyze_ICMP(ptr,lest);
	}

	return 0;
		
}



int print_EtherHeader(struct ether_header *eh,FILE *fp){

    char buf[80];
    fprintf(fp,"=============== Ether Header info =================\n");
    fprintf(fp,"ether target host = %s\n",MACaddress_int_to_str(eh->ether_dhost,buf,sizeof(buf)));
    fprintf(fp,"ether source host = %s\n",MACaddress_int_to_str(eh->ether_shost,buf,sizeof(buf)));

    fprintf(fp,"ether_type = %02X",ntohs(eh->ether_type));

    if(ntohs(eh->ether_type)==ETH_P_IP){

    	fprintf(fp, " [IP]\n");
    
    }else{
    	fprintf(fp, " [undifined]\n");
    }

    fprintf(fp,"===============Ether Header info end=================\n\n");

    return 0;

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

    fprintf(fp, "version : %u\n", iphdr->version);
    fprintf(fp, "header length : %u\n",iphdr->ihl);
    fprintf(fp, "type of service : %x\n",iphdr->tos);
    fprintf(fp, "packet total size : %u\n",ntohs(iphdr->tot_len));
    fprintf(fp, "protocol : %u ",iphdr->protocol);

    if((iphdr->protocol)<=17){
        fprintf(fp, "[%s]\n",protocol[iphdr->protocol]);
    }else{
        fprintf(fp, "undifined\n");
    }

    fprintf(fp, "Source IP:%s\n", IP_address_int_to_IP_address_str(iphdr->saddr,buff,sizeof(buff)));
    fprintf(fp, "target IP:%s\n", IP_address_int_to_IP_address_str(iphdr->daddr,buff,sizeof(buff)));

    fprintf(fp, "============IP info end=======================\n");

    return 0;
}

int analyze_ICMP(u_char *data,int size){

	u_char *ptr;
	int lest;

	ptr=data;
	lest=size;
	struct icmp *icmp;

	icmp=(struct icmp *)ptr;


	print_ICMP(icmp,stdout,ptr,lest,f_data);

	return 0;

}

int print_ICMP(struct icmp *icmp,FILE *fp1,u_char *data,int lest,FILE *fp2){

	static char *icmp_type[]={

		"Echo Reply",
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

	u_char *ptr=data;

	struct icmp_hdr* icmp_hdr;
	icmp_hdr=(struct icmp_hdr*)ptr;
	

	fprintf(fp1, "\n===============ICMP info=================\n");
	
	if(icmp->icmp_type<=18){
		fprintf(fp1, "%s\n",icmp_type[icmp_hdr->type]);
	}else{
		fprintf(fp1, "undifined\n");
	}

	fprintf(fp1, "icmp code=%u\n",icmp_hdr->code);
	fprintf(fp1, "icmp check sum:%u\n",ntohs(icmp_hdr->cksum));

	int i;
	int data_length;

	if(icmp_hdr->type==0&&icmp_hdr->type==0){//Echo Request

		uint8_t *data_ex=(struct icmp_hdr *)(icmp_hdr+1);
		data_length=(lest-sizeof(struct icmp_hdr));

		fprintf(fp1, "icmp id:%u\n",ntohs(icmp_hdr->iden));//4
		fprintf(fp1, "icmp sequence:%u\n",ntohs(icmp_hdr->seqnum));//4
		fprintf(fp1, "data size:%ubytes\n", data_length);
		fprintf(fp1, "raw data(hex)\n\n" );

		for(i=0;i<data_length;i++){
			
			if(i==0){
			}else if(i%16==0){
				fprintf(fp1, "\n");
			}
			
			fprintf(fp1,"%02x ", data_ex[i] );
			
		}		

		fwrite(data_ex,1,data_length,fp2);

	}else if(icmp->icmp_type==8){//Echo Request
		fprintf(fp1, "icmp id:%u\n",ntohs(icmp_hdr->iden));
		fprintf(fp1, "icmp sequence:%u\n",ntohs(icmp_hdr->seqnum));
	}

    fprintf(fp1, "\n\n===============ICMP info end=================\n\n");

    return 0;

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





