/*
 * PcapWrap.h
 *
 *  Created on: 2011. 6. 23.
 *      Author: root
 */

#ifndef PCAPWRAP_H_
#define PCAPWRAP_H_

#include <QtCore>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>


class PcapWrap {

	struct printer {
	  	pcap_handler f;
	  	int	type;
	};

public:
	PcapWrap();
	virtual ~PcapWrap();

    pcap_t	*pd;

    int		sockfd;
    char		*device;
    char		*filter_rule;
    struct printer printers[];

    //void packet_analysis(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
    pcap_handler lookup_printer(int type);
    void process();
    void close();
    void setWidget(QWidget *obj);
private:

};

#endif /* PCAPWRAP_H_ */
