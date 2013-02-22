/*
 * pcapwrap_lib.h
 *
 *  Created on: 2011. 6. 23.
 *      Author: root
 */

#ifndef PCAPWRAP_LIB_H_
#define PCAPWRAP_LIB_H_
#include "udpdump.h"

#define PROMISCUOUS	1

struct iphdr	*iph;
struct tcphdr	*tcph;
struct udphdr	*udph;
struct icmp	   *icmph;
int		pflag;
int		rflag;
int	   eflag;
int		cflag;
int		chcnt;

UdpDump *widget;

#endif /* PCAPWRAP_LIB_H_ */
