#include "pcap_learning.h"


int main (){

	pcap_learing::PcapLearning * cap = new pcap_learing::PcapLearning();

	if(cap->findDevice() == -1){
		return -1;
	}

	if(cap->getDeviceInfo() ==-1){
		return -1;
	}

	if(cap->pcapOpenLive()==-1){
		return -1;
	}

	if(cap->pcapCompile("host www.google.com")==-1){
		return -1;
	}

	if(cap->pcapSetFilter()==-1){
		return -1;
	}

	cap->pcapLoop();

	cap->pcapClose();

	delete cap;
}