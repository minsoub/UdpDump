/*
 * PcapWrap.cpp
 *
 *  Created on: 2011. 6. 23.
 *      Author: root
 */
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "PcapWrap.h"

#include "pcapwrap_lib.h"

#include <QtCore>





void packet_analysis(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p)
{
	int j, temp;
	unsigned int length = h->len;
	struct ether_header *ep;
	unsigned short ether_type;
	unsigned char *tcpdata, *udpdata, *icmpdata, temp_char;
	register unsigned int i;

	chcnt = 0;

	if (rflag)
	{
		while(length--) {
			printf("%02x ", *(p++));
			if ((++chcnt % 16) == 0) printf("\n");
		}
		fprintf(stdout, "\n");
		return;
	}

	length -= sizeof(struct ether_header);

	// ethernet header mapping
	ep = (struct ether_header *)p;
	// ethernet header 14 bytes를 건너 뛴 포인터
	p += sizeof(struct ether_header);
	// datalink type
	ether_type = ntohs(ep->ether_type);

	printf("\n");
	// Ethernet frame이 IEEE802인 경우 ether_type 필드가 길이 필드가 된다.
	if (ether_type <= 1500) {

	}else {
		if (eflag) {
			//dump->setData("abc");
			widget->setData("abc");
			widget->repaint();

			printf("\n\n====================== Datalink layer =========================\n");
			for (j=0; j<ETH_ALEN; j++) {
				printf("%X", ep->ether_shost[j]);
				if (j != 5) printf(":");
			}
			printf("  --------------> ");
			for (j=0; j<ETH_ALEN; j++) {
				printf("%X", ep->ether_dhost[j]);
				if (j != 5) printf(":");
			}

			printf("\nether_type -> %X\n", ntohs(ep->ether_type));
		}

		iph = (struct iphdr *) p;
		i = 0;
		if (ntohs(ep->ether_type)== ETHERTYPE_IP) {   // IP Packet
			printf("\n\n =======================  IP HEADER ========================\n");
			printf("%d ----------->", iph->saddr);  //inet_ntoa(iph->saddr));
			printf("%d\n",            iph->saddr);  // inet_ntoa(iph->daddr));
			printf("Version :              %d\n", iph->version);
			printf("Header Length :        %d\n", iph->ihl);
			printf("Service :              %#x\n", iph->tos);
			printf("Total Length :         %d\n", ntohs(iph->tot_len));
			printf("Identification :       %d\n", ntohs(iph->id));
			printf("Fragment Offset :      %d\n", ntohs(iph->frag_off));
			printf("Time to Live :         %d\n", iph->ttl);
			printf("Checksum :             %d\n", ntohs(iph->check));


			if(iph->protocol == IPPROTO_TCP) {
				tcph = (struct tcphdr *) (p + iph->ihl * 4);
				// tcp data는
				tcpdata = (unsigned char *) (p + (iph->ihl*4) + (tcph->doff * 4));
				printf("\n\n===================   TCP HEADER   ===================\n");
				printf("Source Port:              %d\n", ntohs(tcph->source));
				printf("Destination Port:         %d\n", ntohs(tcph->dest));
				printf("Sequence Number:          %d\n", ntohl(tcph->seq));
				printf("Acknowledgement Number:   %d\n", ntohl(tcph->ack_seq));
				printf("Data Offset:              %d\n", tcph->doff);
				printf("Window:                   %d\n", ntohs(tcph->window));
				printf("URG:%d ACK:%d PSH:%d RST:%d SYN:%d FIN:%d\n",
				tcph->urg, tcph->ack, tcph->psh, tcph->rst,
				tcph->syn, tcph->fin, ntohs(tcph->check),
				ntohs(tcph->urg_ptr));
				printf("\n===================   TCP DATA(HEX)  =================\n");
				chcnt = 0;
				for(temp = (iph->ihl * 4) + (tcph->doff * 4); temp <= ntohs(iph->tot_len) - 1; temp++) {
					printf("%02x ", *(tcpdata++));
					if( (++chcnt % 16) == 0 ) printf("\n");
				}
				if (pflag) {
				   tcpdata = (unsigned char *) (p + (iph->ihl*4) + (tcph->doff * 4));
				   printf("\n===================   TCP DATA(CHAR)  =================\n");
				   for(temp = (iph->ihl * 4) + (tcph->doff * 4); temp <= ntohs(iph->tot_len) - 1; temp++) {
						temp_char = *tcpdata;
						if ( (temp_char == 0x0d) && ( *(tcpdata+1) == 0x0a ) ) {
							fprintf(stdout,"\n");
							tcpdata += 2;
							temp++;
							continue;
						}
						temp_char = ( ( temp_char >= ' ' ) && ( temp_char < 0x7f ) )? temp_char : '.';
						printf("%c", temp_char);
						tcpdata++;
				   }
				}
				printf("\n>>>>> End of Data >>>>>\n");
			}
			else if(iph->protocol == IPPROTO_UDP) {
				udph = (struct udphdr *) (p + iph->ihl * 4);
				udpdata = (unsigned char *) (p + iph->ihl*4) + 8;
				printf("\n==================== UDP HEADER =====================\n");
				printf("Source Port :      %d\n",ntohs(udph->source));
				printf("Destination Port : %d\n", ntohs(udph->dest));
				printf("Length :           %d\n", ntohs(udph->len));
				printf("Checksum :         %x\n", ntohs(udph->check));
						printf("\n===================  UDP DATA(HEX)  ================\n");
				chcnt = 0;
				for(temp = (iph->ihl*4)+8; temp<=ntohs(iph->tot_len) -1; temp++) {
				   printf("%02x ", *(udpdata++));
				   if( (++chcnt % 16) == 0) printf("\n");
				}

				udpdata = (unsigned char *) (p + iph->ihl*4) + 8;
				if(pflag) {
					printf("\n===================  UDP DATA(CHAR)  ================\n");
					for(temp = (iph->ihl*4)+8; temp<=ntohs(iph->tot_len) -1; temp++)  {
						temp_char = *udpdata;
						if ( (temp_char == 0x0d) && ( *(udpdata+1) == 0x0a ) ) {
							fprintf(stdout,"\n");
							udpdata += 2;
							temp++;
							continue;
						}
						temp_char = ( ( temp_char >= ' ' ) && ( temp_char < 0x7f ) )? temp_char : '.';
						printf("%c", temp_char);
						udpdata++;
					}
				}

				printf("\n>>>>> End of Data >>>>>\n");
			}
			else if(iph->protocol == IPPROTO_ICMP) {
				icmph = (struct icmp *) (p + iph->ihl * 4);
				icmpdata = (unsigned char *) (p + iph->ihl*4) + 8;
				printf("\n\n===================   ICMP HEADER   ===================\n");
				printf("Type :                    %d\n", icmph->icmp_type);
				printf("Code :                    %d\n", icmph->icmp_code);
				printf("Checksum :                %02x\n", icmph->icmp_cksum);
				printf("ID :                      %d\n", icmph->icmp_id);
				printf("Seq :                     %d\n", icmph->icmp_seq);
				printf("\n===================   ICMP DATA(HEX)  =================\n");
				chcnt = 0;
				for(temp = (iph->ihl * 4) + 8; temp <= ntohs(iph->tot_len) - 1; temp++) {
					printf("%02x ", *(icmpdata++));
					if( (++chcnt % 16) == 0 ) printf("\n");
				}
				printf("\n>>>>> End of Data >>>>>\n");
		   }
		}
	}
}

PcapWrap::PcapWrap() {
	// TODO Auto-generated constructor stub

}

PcapWrap::~PcapWrap() {
	// TODO Auto-generated destructor stub
}

pcap_handler PcapWrap::lookup_printer(int type)
{
	struct printer *p;

	for (p = printers; p->f; ++p)
		if (type == p->type)
			return p->f;

	qDebug("unknown data link type........");
}

void PcapWrap::process()
{
	struct bpf_program fcode;
	pcap_handler printer;
	char ebuf[PCAP_ERRBUF_SIZE];
	int  c, i, snaplen, size, packetcnt;
	bpf_u_int32 myself, localnet, netmask;
	unsigned char *pcap_userdata;

	filter_rule = "udp port 8001";
	opterr = 0;

	if ((device = pcap_lookupdev(ebuf)) == NULL) {
		qDebug() << ebuf;
		return;
	}

	fprintf(stdout, "device = %s\n", device);

	snaplen = 1024 * 1024;

	pd = pcap_open_live(device, snaplen, PROMISCUOUS, 1000, ebuf);
	if (pd == NULL) {
		qDebug() << ebuf;
		return;
	}
	i = pcap_snapshot(pd);
	if (snaplen < i) {
		qDebug() << ebuf;
		return;
	}

	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		qDebug() << ebuf;
		return;
	}

	setuid(getuid());

	if (pcap_compile(pd, &fcode, filter_rule, 0, netmask) < 0) {
		qDebug() << ebuf;
		return;
	}

	if (pcap_setfilter(pd, &fcode) < 0) {
		qDebug() << ebuf;
		return;
	}

	fflush(stderr);

	printers[0].f = packet_analysis;
	printers[0].type = DLT_IEEE802;

	printers[1].f = packet_analysis;
	printers[1].type = DLT_EN10MB;

	printers[2].f = NULL;
	printers[2].type = 0;

	pflag = 1;

	//dump = this;

	printer = lookup_printer(pcap_datalink(pd));
	pcap_userdata = 0;
	packetcnt = 0;		// 무한대

	if (pcap_loop(pd, packetcnt, printer, pcap_userdata) < 0) {
		qDebug() << "pcap_loop error";
		return;
	}
	pcap_close(pd);

	return;
}

void PcapWrap::close()
{
	pcap_close(pd);
}

void PcapWrap::setWidget(QWidget *widget)
{
	widget = (UdpDump *)widget;
}
