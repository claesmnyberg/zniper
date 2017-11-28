
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

/*  
 * We store the connections in a linked list.
 * This sucks, but srcip:port->dstip:port is the same
 * connection as dstip:port->srcip:port, which makes it
 * hard to find it in for example a binary tree since
 * we need to know who the source is in the tree-node. 
 * TODO: Fix the bad O(n) complexity
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <pthread.h>
#include "zniper.h"

/* Global variables */
extern struct options opt;

/* Local variables */
static struct conn_node *first = NULL;
static struct conn_node *last = NULL;
static struct conn *connarr; /* Connections to display */
static size_t connarrsize = 512;
static int rebuild_array;

/* The tree of connections must be locked when accessed */
pthread_mutex_t conn_tree;

/* Local procedures */
static void conn_addlast(struct conn *);
static int conn_del(struct conn *conn);
static void conn_setstr(struct conn *);


/*
 * Update connection
 */
void
conn_manage(struct conn *conn, u_short flags)
{
	struct conn *connpt;
	int sigraise = 0;

	/* Lock the tree */
	pthread_mutex_lock(&conn_tree);

    /* Aborted connection, remove it */
    if (TCP_RST(flags)) {
        writestatus(2, "Got reset packet, removing connection '%s'",
            conn_sock2str(conn));
        conn_del(conn);
		rebuild_array++;
		if (conn->twh & CONN_ESTABLISHED)
			sigraise++;
        goto finished;
    }

	connpt = conn_get(conn, NULL);

	/* SYN packet, add the connection attempt */
	if (TCP_SYN(flags) && !TCP_ACK(flags)) {
		conn->twh = CONN_SYN_SENT;
		writestatus(1, "Connection attempt '%s'", conn_sock2str(conn));
		if (connpt == NULL) 
			conn_addlast(conn);
		goto finished;
	}
	
	/* The connection does not exist */
	if (connpt == NULL) {

		if (opt.grab) {
			writestatus(2, "Possible connection '%s'",
				conn_sock2str(conn));
			conn->twh = CONN_GRABBED;
			conn_addlast(conn);
		}
		goto finished;
	}
	
	else if (TCP_SYN(flags) && TCP_ACK(flags)) {

		if (conn->cd.src != connpt->cd.dst) {
			writestatus(3, "Warning: Received SYN ACK from initiator in '%s'", 
				connpt->scka);
		}
		else
			connpt->twh |= CONN_SYN_ACK_SENT;
	}

	else if (TCP_FIN(flags)) {
		
		/* source -> dest */
		if (conn->cd.src == connpt->cd.src)
			connpt->twh |= CONN_FIN_FROM_SRC;

		/* dest -> source */
		else
			connpt->twh |= CONN_FIN_FROM_DST;
	}

	else if (TCP_ACK(flags)) {
		
		/* source -> dest */
		if (conn->cd.src == connpt->cd.src) {
			
			/* Finishing connection */
			if (connpt->twh & CONN_FIN_FROM_DST) {
				connpt->twh |= CONN_DEST_FINISHED;	

				/* Connection finished */
				if (connpt->twh & CONN_SOURCE_FINISHED) {
					writestatus(2, "Removing FINished connection '%s'",
						connpt->scka);
					conn_del(conn);
					rebuild_array++;
					sigraise++;
					goto finished;
				}
			}

			/* Connection established */
			if (!(connpt->twh & CONN_ESTABLISHED)) {
				if (connpt->twh & CONN_SYN_ACK_SENT) {

					connpt->twh |= CONN_ESTABLISHED;
					
					/* We might have missed the SYN ACK packet .. */
					if (!(connpt->twh & CONN_SYN_ACK_SENT)) 
						writestatus(2, "Missing SYN ACK, marking '%s' as a connection anyway", 
							connpt->scka);
			
					writestatus(0, "New connection '%s'", connpt->scka);
					rebuild_array++;
					sigraise++;
				}
			}
		}

		/* dest -> source */
		else if (conn->cd.src == connpt->cd.dst) {

			/* Finishing connection */
			if (connpt->twh & CONN_FIN_FROM_SRC) {
				connpt->twh |= CONN_SOURCE_FINISHED;

				/* Connection finished */
				if (connpt->twh & CONN_DEST_FINISHED) {
					writestatus(2, "Removing FINished connection '%s'",
						connpt->scka);
					conn_del(conn);
					rebuild_array++;
					sigraise++;
					goto finished;
				}
			}
			
			if (!(connpt->twh & CONN_ESTABLISHED)) {
				if (connpt->twh & CONN_SYN_ACK_SENT) {

					connpt->twh |= CONN_ESTABLISHED;
					
					/* We might have missed the SYN ACK packet .. */ 
					if (!(connpt->twh & CONN_SYN_ACK_SENT)) 
						writestatus(2, "Missing SYN ACK, marking '%s' as a connection anyway", 
							connpt->scka);
			
					writestatus(0, "New connection '%s'", connpt->scka);
					rebuild_array++;
					raise(SIGUSR1);
				}
			}
		}
		if (connpt->twh & CONN_GRABBED)
			if (connpt->ackp < CONN_GRABBED_ACKS) {
				
				if (++connpt->ackp == CONN_GRABBED_ACKS) 
					writestatus(0, "Spotted connection '%s'", connpt->scka);
			}
	}

	/* Do the actual update */
	connpt->lupd = conn->lupd;
	if (conn->cd.src == connpt->cd.src) {
		connpt->srcseq = conn->srcseq;
		connpt->dstseq = conn->dstseq;
	}
	else {
		connpt->srcseq = conn->dstseq;
		connpt->dstseq = conn->srcseq;
	}

finished:
	pthread_mutex_unlock(&conn_tree);
	rebuild_array++;
	if (sigraise)
		raise(SIGUSR1);
}

/*
 * Get the array of connections and write the number of 
 * connections in the array to num if num is not NULL.
 */
const struct conn *
conn_getarr(u_int *num)
{
	struct conn_node *curr;
	static size_t numconns = 0;

	pthread_mutex_lock(&conn_tree);

rebuild_array++;
	if (first == NULL)
		rebuild_array = 0;
	
	if (rebuild_array) {
		curr = first;
		numconns = 0;
		while (curr != NULL) {
			
			/* Remove old connection attempts and idle "connections" which has a FIN 
			 * packet in some direction since we might have missed some ACK.
			 * If we didn't, the connection will appear again as soon as data is sent. */
			if (ISIDLE(curr->conn) && 
					(HASFIN(curr->conn) || (curr->conn->twh == CONN_SYN_SENT))) {
				struct conn_node *tmp = curr;

				writestatus(4, "Removed %s '%s'", 
					HASFIN(curr->conn) ? "idle FIN connection": "old connection attempt", 
					conn_sock2str(curr->conn));
				
				CONN_UNLINK(curr);
				curr = tmp->next;
				continue;
			}

        	if (CONN_DISPLAY(curr->conn)) {

            	/* Add space to the array */
            	if (connarr == NULL)
                	connarr = (struct conn *)memordie(connarrsize*sizeof(struct conn));

            	/* Out of memory */
            	else if (numconns >= (connarrsize-2)) {
                	struct conn *tmp;

                	connarrsize*=2;
                	tmp = (struct conn *)memordie(connarrsize*sizeof(struct conn));

                	memcpy(tmp, connarr, numconns*sizeof(struct conn));
                	free(connarr);
                	connarr = tmp;
            	}

				/* Delete old */
				if (connarr[numconns].lupd != 0)
					FREE_CONN_MEM(connarr[numconns]);

            	/* Copy information */
            	memcpy(&connarr[numconns], curr->conn, sizeof(struct conn));
            	connarr[numconns].srch = strdup(curr->conn->srch);
            	connarr[numconns].dsth = strdup(curr->conn->dsth);
            	/* No need for this */
            	connarr[numconns].scka = strdup(curr->conn->scka);
            	numconns++;
        	}
			curr = curr->next;
		}

		/* Mark end of connections */
		if (connarr != NULL && connarr[numconns].lupd != 0) {
			FREE_CONN_MEM(connarr[numconns]);
			connarr[numconns].lupd = 0;
		}
	}

	/* Sort the array */

	pthread_mutex_unlock(&conn_tree);
	rebuild_array = 0;
	if (num != NULL)
		*num = numconns;
	return((const struct conn *)connarr);
}


/*
 * Translate connection socket to a string
 */
char *
conn_sock2str(struct conn *conn)
{
    static char buf[512];
	char srcas[16];
	char dstas[16];

	memset(buf, 0x00, sizeof(buf));
	memset(srcas, 0x00, sizeof(srcas));
	memset(dstas, 0x00, sizeof(dstas));
	
	net_ntoa(conn->cd.src, srcas);
	net_ntoa(conn->cd.dst, dstas);

	/* If a SYN packet was received, we know who requested 
	 * the connection */
    snprintf(buf, sizeof(buf)-1, "%s:%u %s %s:%u", 
		srcas, ntohs(conn->cd.srcp), (conn->twh & CONN_SYN_SENT) ? "->" : "<->",
		dstas, ntohs(conn->cd.dstp));

    return(buf);
}

/*
 * Get connection
 */
struct conn *
conn_get(struct conn *conn, struct conn *save)
{
	struct conn_node *curr;

	if (first == NULL)
		return(NULL);

	for (curr = first; curr != NULL; curr = curr->next) {
		if (!conn_cmp(curr->conn, conn)) {
			if (save != NULL)
				memcpy(save, curr->conn, sizeof(struct conn));
			return(curr->conn);
		}
	}

	return(NULL);
}

/*
 * Set the string pointers in connection
 *
 */
static void
conn_setstr(struct conn *conn)
{
	if (opt.resolve) {
		u_char *ipas;
		
		ipas = net_hostname2(conn->cd.src);
		conn->srch = (ipas == NULL) ? strdup("unknown") : strdup(ipas);
		ipas = net_hostname2(conn->cd.dst);
		conn->dsth = (ipas == NULL) ? strdup("unknown") : strdup(ipas);
	}
	else {
		conn->srch = strdup("");
		conn->dsth = strdup("");
	}
	conn->scka = strdup(conn_sock2str(conn));
}


/*
 * Delete connection
 * Returns 1 if connection was found and removed, 0 otherwise
 */
static int
conn_del(struct conn *conn)
{
	struct conn_node *curr;

	if (first == NULL)
		return(0);

	for (curr = first; curr != NULL; curr = curr->next) {
		if (!conn_cmp(curr->conn, conn)) {

			writestatus(5, "Removed connection '%s'",
				conn_sock2str(curr->conn));

			CONN_UNLINK(curr);
			return(1);
		}
	}

	writestatus(5, "Warning: Attempt to remove nonexisting connection '%s'", 
		conn_sock2str(conn));
	return(0);
}


/* 
 * Add connection to end of list
 */
static void
conn_addlast(struct conn *conn)
{
	struct conn_node *curr;

	/* Create entry */
	curr = (struct conn_node *)memordie(sizeof(struct conn_node));
	curr->conn  = (struct conn *)memordie(sizeof(struct conn));
	memcpy(curr->conn, conn, sizeof(struct conn));
	curr->conn->start = conn->lupd;
	curr->conn->lupd = conn->lupd;
	curr->conn->twh = conn->twh;
	curr->conn->ackp = 0;
	conn_setstr(curr->conn);

	if (first == NULL) {
		first = curr;
		last = first;
	}
	else {
		last->next = curr;
		curr->prev = last;
		last = curr;
	}
	writestatus(5, "Added '%s' to list of potential connections", 
		conn_sock2str(conn));
}

u_char *
hexstr(u_char *str, int len)
{
	int i;
	u_char *pt = calloc(1, 2*len+1);


	for (i=0; i<len; i++)
		snprintf(&pt[2*i], 2*len, "%02x", str[i]);
	return(pt);
}


/*
 * Compare two connections FIXME
 */
int
conn_cmp(const struct conn *c1, const struct conn *c2)
{
	/* Same direction as the first packet spotted in the connection */
	if ((c1->cd.src == c2->cd.src) && (c1->cd.dst == c2->cd.dst) &&
			(c1->cd.srcp == c2->cd.srcp) && (c1->cd.dstp == c2->cd.dstp)) 
		return(0);

	/* Reversed */
	if ((c1->cd.src == c2->cd.dst) && (c1->cd.dst == c2->cd.src) &&
			(c1->cd.srcp == c2->cd.dstp) && (c1->cd.dstp == c2->cd.srcp)) 
		return(0);

	/* Not equal (no need to check for smaller or greater now) */
	return(1);
}
