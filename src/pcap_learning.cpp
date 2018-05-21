#include <pcap_learning.h>

namespace pcap_learing{
PcapLearning::PcapLearning(){

	this->packet_count_limit = 1;
   	this->timeout_limit = 10000;
   	this->handle = NULL;

}

PcapLearning::~PcapLearning(){

}

int PcapLearning::findDevice(){

	char * device_name ;
	char error_buffer[PCAP_ERRBUF_SIZE];

	device_name = pcap_lookupdev(error_buffer);

	if (device_name == NULL) {
		printf("Error finding device: %s\n", error_buffer);
		return -1;
	}

	printf("Network device found: %s\n", device_name);
	this->device = device_name;
	return 0;

}

int PcapLearning::getDeviceInfo(){

	char error_buffer[PCAP_ERRBUF_SIZE];
    struct in_addr address;
    char ip[13];
    char subnet_mask[13];

	if(pcap_lookupnet(this->device.c_str(),&this->ip_raw,&this->subnet_mask_raw,error_buffer)==-1){
		return -1;
	}

	address.s_addr = this->ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
        perror("inet_ntoa"); /* print error */
        return -1;
    }

    this->ipAddress = ip;

    address.s_addr = this->subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL) {
        perror("inet_ntoa");
        return -1;
    }

    this->subnetMask = subnet_mask;
    
    std::cout<<this->ipAddress<<std::endl;
    std::cout<<this->subnetMask<<std::endl;
   	std::cout<<this->device<<std::endl;

	return 0;

}

void PcapLearning::my_packet_handler(u_char *args,const struct pcap_pkthdr *packet_header,const u_char *packet)
{
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	std::cout<<"Packet number : "<<count<<std::endl;
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		std::cout<<"****Invalid IP header length: "<<size_ip<< " bytes"<<std::endl;
		return;
	}

	/* print source and destination IP addresses */
	std::cout<<" From: "<<inet_ntoa(ip->ip_src)<<std::endl;
	std::cout<<"   To: "<<inet_ntoa(ip->ip_dst)<<std::endl;
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			std::cout<<"	Protocol: TCP"<<std::endl;
			break;
		case IPPROTO_UDP:
			std::cout<<"	Protocol: UDP"<<std::endl;
			return;
		case IPPROTO_ICMP:
			std::cout<<"	Protocol: ICMP"<<std::endl;
			return;
		case IPPROTO_IP:
			std::cout<<"	Protocol: IP"<<std::endl;
			return;
		default:
			std::cout<<"	Protocol: unknown"<<std::endl;
			return;
	}
	

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		std::cout<<"   * Invalid TCP header length: "<<size_tcp<<"bytes"<<std::endl;
		return;
	}

	std::cout<<"   Src port:" <<ntohs(tcp->th_sport)<<std::endl;
	std::cout<<"   Dst port:" <<ntohs(tcp->th_dport)<<std::endl;
	
	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	if (size_payload > 0) {
		const u_char *ch = (u_char*)payload;
		std::cout<<"payload "<<size_payload<<"bytes"<<std::endl;
		for(int i=0;i<size_payload;i++){
			if (isprint(*ch))
				std::cout<<*ch;
			else
				std::cout<<".";
			ch++;
		}
	}

	std::cout<<std::endl;


return;
}



int PcapLearning::pcapOpenLive(){
	char error_buffer[PCAP_ERRBUF_SIZE];
    
	this->handle = pcap_open_live(this->device.c_str(),BUFSIZ,0,this->timeout_limit,error_buffer);
	if (this->handle == NULL) {
		 std::cout<<"Couldn't open device "<<error_buffer<<std::endl;
		 return(-1);
	 }

	 return 0;

}

int PcapLearning::pcapCompile(std::string filter){

	if(pcap_compile(this->handle,&this->fp,filter.c_str(),0,this->ip_raw)==-1){
		 std::cout<<"pcap_compile error "<<std::endl;
		 return(-1);		
	}	

	return 0;
}

int PcapLearning::pcapSetFilter(){

    if(pcap_setfilter(this->handle,&this->fp) == -1){ 
    	std::cout<<"pcap_set filter error "<<std::endl;
    	return -1;
    }

	return 0;
}


void PcapLearning::pcapLoop(){

	pcap_loop(this->handle, -1, this->my_packet_handler, NULL);

}

void PcapLearning::pcapClose(){
	pcap_close(this->handle);
}


}


