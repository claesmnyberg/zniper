/*
 *  sniff.c - zniper packet capture routines.
 *
 *  Copyright (c) 2002 Claes M. Nyberg <pocpon@fuzzpoint.com>
 *  All rights reserved, all wrongs reversed.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. The name of author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 *  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include "zniper.h"

/* Global variables */
extern struct options opt;

/* Local functions */
static void packet_analyze(u_char *, const struct pcap_pkthdr *, const u_char *);
struct conn *createconn(IPv4_hdr *, TCP_hdr *, struct conn *);


/*
 * Capture packets and keep track of connections
 */
void *
sniff(void *capture)
{
	struct capture *cap = (struct capture *)capture;

	/* Capture packets until an error occur and send them to
	 * packet_analyze().
	 * If the network goes down, we sleep for five seconds 
	 * and try again. */
	for (;;) {
		pcap_loop(cap->cap_pcapd, -1, packet_analyze, (u_char *)cap);
		
		if (errno != ENETDOWN)
			break;

		writestatus(0, "Warning: %s (sleeping 20 seconds)\n", 
			strerror(errno));
	
		sleep(5);
	}
	
    /* Hopefully unreached */
    writestatus(0, "Error: pcap_loop(): %s\n", strerror(errno));
	pthread_exit(NULL);
	return(NULL);
}


/*
 * Examine all the packets
 */
static void
packet_analyze(u_char *cap, 
	const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	register IPv4_hdr *iph;
	register TCP_hdr *tcph;
	struct conn conn;

	/* Check that packet length is OK */
	if ( (pkthdr->len) <= (((struct capture *)cap)->cap_offst + sizeof(IPv4_hdr))) 
		return;

	/* Create IP header */
	iph = (IPv4_hdr *)(packet + ((struct capture *)cap)->cap_offst);

	/* Only IPv4 is supported for now .. */
	if (iph->ip_ver != 4) 
		return;

	/* Check for TCP (should never happend since we filter out TCP traffic) */
	if (iph->ip_prot != PROTO_TCP) 
		return;

	/* Create TCP header */
	tcph = (TCP_hdr *)(packet + ((struct capture *)cap)->cap_offst + (iph->ip_hlen)*4);	

	createconn(iph, tcph, &conn);
	conn_manage(&conn, tcph->tcp_flgs);
}

/*
 * Create connection structure out of TCP packet
 */
struct conn *
createconn(IPv4_hdr *iph, TCP_hdr *tcph, struct conn *conn)
{
	memset(conn, 0x00, sizeof(struct conn));
	conn->cd.src = iph->ip_sadd;
	conn->cd.srcp = tcph->tcp_sprt;
	conn->cd.dst = iph->ip_dadd;
	conn->cd.dstp = tcph->tcp_dprt;
	conn->lupd = time(NULL);
	conn->srcseq = tcph->tcp_seq;
	conn->dstseq = tcph->tcp_ack;
	return(conn);
}
