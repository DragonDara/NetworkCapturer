#if !defined(WIN32) && !defined(WINx64)
#include <netinet/in.h> // this is for using ntohs() and htons() on non-Windows OS's
#endif
#include "headers/httpsf.hpp"
#include "stdlib.h"
#include <iostream>
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/PlatformSpecificUtils.h"
#include "pcapplusplus/SSLLayer.h"
#include "pcapplusplus/SSLHandshake.h"
#include "pcapplusplus/SSLCommon.h"
#include "pcapplusplus/SystemUtils.h"
#include <string.h>
#include <time.h>

using namespace std;
using namespace pcpp;

Https https;

#define DEFAULT_CALC_RATES_PERIOD_SEC 2


void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
}
struct Exm{
};
struct SSLPacketArrivedData
{
	void getSSLLayer(Packet* packet){
	
		IPv4Layer* ipLayer = packet->getLayerOfType<IPv4Layer>();
		//IPv4Option* ipOptions = ipLayer->getFirstOption<IPv4Option>();
		//IPv4TimestampOptionValue timestamp = ipLayer->getFirstOption().getTimestampOptionValue<IPv4TimestampOptionValue>();
		TcpLayer* tcpLayer = packet->getLayerOfType<TcpLayer>();
		if (ipLayer == NULL)
		{
			printf("Something went wrong, couldn't find IPv4 layer\n");
		}
		if(packet->isPacketOfType(SSL)){
			
			// verify packet is TCP and SSL/TLS
			pcpp::SSLLayer* sslLayer = packet->getLayerOfType<pcpp::SSLLayer>();
			if (sslLayer == NULL)
			{
				printf("Something went wrong, couldn't find SSL/TLS layer\n");
			}
			pcpp::SSLRecordType recType = sslLayer->getRecordType();
			if(recType == SSL_HANDSHAKE){
				pcpp::SSLHandshakeLayer* handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer*>(sslLayer);
				if (handshakeLayer == NULL)
					printf("Something went wrong, couldn't find handshakeLayer\n");

				// try to find client-hello message
				pcpp::SSLClientHelloMessage* clientHelloMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();

				// collect client-hello stats
				if (clientHelloMessage != NULL)
				{
					time_t my_time = time(NULL);
					https.timestamp_s =ctime(&my_time);
					https.ipv4s_s = ipLayer->getSrcIpAddress().toString();
					https.ipv4d_s = ipLayer->getDstIpAddress().toString();
					https.sport_s = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
					https.dport_s = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
					SSLServerNameIndicationExtension* sniExt = clientHelloMessage->getExtensionOfType<SSLServerNameIndicationExtension>();
					if (sniExt != NULL){
						https.hostname_s = sniExt->getHostName();
						insert_https(https);
					}
					
				}

				// try to find server-hello message
				pcpp::SSLServerHelloMessage* serverHelloMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLServerHelloMessage>();

				// collect server-hello stats
				if (serverHelloMessage != NULL)
				{
					time_t my_time = time(NULL);
					SSLCipherSuite* cipherSuite = serverHelloMessage->getCipherSuite();
					https.timestamp_s =ctime(&my_time);
					https.ipv4s_s = ipLayer->getSrcIpAddress().toString();
					https.ipv4d_s = ipLayer->getDstIpAddress().toString();
					//cout << "Timestamp: " << <<endl;
					https.sport_s = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
					https.dport_s = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
					https.cipher_s = cipherSuite->asString();
					switch(serverHelloMessage->getHandshakeVersion()){
						case 2:
							https.version_s ="SSLv2";
							break;
						case 768:
							https.version_s ="SSLv3";
							break;
						case 769:
							https.version_s ="TLSv1.0";
							break;
						case 770:
							https.version_s ="TLSv1.1";
							break;
						case 771:
							https.version_s ="TLSv1.2";
							break;
						default:
							https.version_s ="unknown protocol";
							break;
					}
					insert_https(https);
				}
			}
			sslLayer = packet->getNextLayerOfType<pcpp::SSLLayer>(sslLayer);
		}
		
	}
};

static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	Packet parsedPacket(packet);
	// let's get the IPv4 layer
	SSLPacketArrivedData* data  = (SSLPacketArrivedData*)cookie;
	data->getSSLLayer(&parsedPacket);
}



int main(int argc, char* argv[])
{
	 if (argc != 2) {
        cout << "Usage: " << argv[0] << " <interface> " << endl;
        return 1;
    }

	pcpp::PortFilter portFilter(443, pcpp::SRC_OR_DST);

	// create a filter instance to capture only TCP traffic
	pcpp::ProtoFilter protocolFilter(pcpp::TCP);

	// create an AND filter to combine both filters - capture only TCP traffic on port 80
	pcpp::AndFilter andFilter;
	andFilter.addFilter(&portFilter);
	andFilter.addFilter(&protocolFilter);

	// set the filter on the devic
    std::string interfaceName = "ens33";
	cout << argv[1] << endl;
	int printRatePeriod = DEFAULT_CALC_RATES_PERIOD_SEC;
    PcapLiveDevice* dev = NULL;
	dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(argv[1]);
    if (dev == NULL){
		cout << "Couldn't find interface by provided IP" << endl;
	}
	if (!dev->open())
	{
		printf("Cannot open device\n");
	}


	dev->setFilter(andFilter);
	Exm exm;
	printf("\nStarting async capture...\n");

	// start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
	dev->startCapture(onPacketArrives, &exm);

	bool shouldStop = false;
	ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	while(!shouldStop)
	{
		PCAP_SLEEP(printRatePeriod);
	}

	// stop capturing packets
	dev->stopCapture();
	dev->close();

}

