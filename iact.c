/*
 *  Copyright (c) 2003 Claes M. Nyberg <pocpon@fuzzpoint.com>
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
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include "zniper.h"

/* Global variables */
extern struct options opt;
extern struct screen screen;
extern struct winframe wframe;
extern pthread_mutex_t conn_tree;

#define KILL_CONN	0x1

/*
 * Automaticly refresh the screen if the keyboard is idle
 */
static void
refresh_handler(int signo)
{
	drawconnwin();
}

/*
 * The interactive loop
 */
void
iact(void)
{
	int c;
	struct conn *cp;
	struct conn conn;
	u_char pkt[sizeof(IPv4_hdr)+sizeof(TCP_hdr)];
	u_long action;

	for (;;) {
		action = 0;

		signal(SIGUSR1, refresh_handler);
		if ( (c = getch()) == ERR) {
			writestatus(0, "Failed to ge input");
			continue;
		}
		signal(SIGUSR1, SIG_IGN);

		switch (c) {
		
			/* Toggle display of idle connections */
			case 'i':
				opt.idle++;
				wframe.hindex = -1;
				break;
		
			/* Toggle status window visibility */
			case 'x':
				opt.statw++;
				raise(SIGWINCH);
				break;

			/* Make connection window smaller */
			case 'c':
				opt.conhp -= (opt.conhp >= 12 ? 2: 0);
				raise(SIGWINCH);
				continue;
				break;

			/* Make connection window bigger */
			case 'C':
				opt.conhp += (opt.conhp <= 78 ? 2: 0);
				raise(SIGWINCH);
				continue;
				break;

			/* Sort by src port, smallest first */
			case 'p':
				opt.sortby = SORT_SRCP;
				drawconnwin();
				break;
				
			/* Sort by src port, descending */
			case 'P':
				opt.sortby = SORT_SRCP_DESC;
				drawconnwin();
				break;

			/* Try to kill the connection */
			case 'k':
				pthread_mutex_lock(&conn_tree);
				cp = conn_get(&wframe.hlconn, &conn);	
				pthread_mutex_unlock(&conn_tree);
				/* Three RST in each direction */
				if (cp != NULL)
					action = KILL_CONN;
				break;

			/* Use the sledge hammer to knock thisone out */
			case 'K':
				break;
			
			/* Toggle resolving of hostnames */
			case 'r':
				opt.resolve++;
				break;

			/* Decrease verbose level */
			case 'v':
				opt.verbose = (opt.verbose == 0 ? 0 : opt.verbose-1);
				writestatus(0, "Verbose level set to %d", opt.verbose);
				continue;
				break;

			/* Increase verbose level */
			case 'V':
				opt.verbose = (opt.verbose >= 5 ? 5 : opt.verbose+1);
				writestatus(0, "Verbose level set to %d", opt.verbose);
				continue;
				break;

			case '+':
			case KEY_UP:
				if (wframe.hindex > 0)
					wframe.hindex--; 
				else
					continue;
				break;

			case '-':
			case KEY_DOWN:
				wframe.hindex++; 
				break;
					
		}

		/* One RST packets in each direction */
		if (action == KILL_CONN) {
			u_char *sip;

			iraw_add_ipv4(pkt, 0x10, 0xdead, 255, conn.cd.dst, conn.cd.src);
			iraw_add_tcp(pkt, conn.cd.dstp, conn.cd.srcp, conn.dstseq, conn.srcseq, 0, RST|ACK, NULL, 0);
			iraw_send_packet(opt.sock_raw, pkt);

			iraw_add_ipv4(pkt, 0x10, 0xdead, 255, conn.cd.src, conn.cd.dst);
			iraw_add_tcp(pkt, conn.cd.srcp, conn.cd.dstp, conn.srcseq, conn.dstseq, 0, RST|ACK, NULL, 0);
			iraw_send_packet(opt.sock_raw, pkt);
			
			writestatus(0, "Injected RST into connection '%s'", conn_sock2str(&conn));
			if (opt.verbose > 0) {
				sip = net_ntoa(conn.cd.src, NULL);
				writestatus(0, " %s:%u > %s:%u R %u:%u(0) ack %u", sip, ntohs(conn.cd.srcp),
					net_ntoa(conn.cd.dst, NULL), ntohs(conn.cd.dstp), conn.dstseq, conn.dstseq, conn.srcseq);
				sip = net_ntoa(conn.cd.src, NULL);
				writestatus(0, " %s:%u > %s:%u R %u:%u(0) ack %u", net_ntoa(conn.cd.dst, NULL), ntohs(conn.cd.dstp),
					sip, ntohs(conn.cd.srcp), conn.srcseq, conn.srcseq, conn.dstseq);
			}
		}
		
		drawconnwin();
	}
}
