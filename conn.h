/*
 *  Copyright (c) 2003 Claes M. Nyberg <cmn@fuzzpoint.com>
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
 * $Id: conn.h,v 1.1.1.1 2004-07-30 11:19:33 cmn Exp $
 */ 

#ifndef _CONN_H
#define _CONN_H

#include <sys/types.h>

/*
 * Connection information
 */
struct conn {

	/* The uniq connection descriptor (network byte order) */
	struct conndesc {
		u_long src;         /* Source IPv4, the sender of the SYN packet */
		u_short srcp;       /* Source port */
		u_long dst;         /* Destination IPv4 */
		u_short dstp;       /* Destination port */
	} cd;

	/* Connection information */
	u_short twh;	/* Three way handshake status */
	u_char ackp;	/* Number of ACK packets received (for grabbed connection) */
	u_long srcseq;	/* Last sequence number seen from source */
	u_long dstseq;	/* Last sequence number seen from destination */

	time_t start;	/* Time when first packet was seen */
	time_t lupd;	/* Last update */

	/* Strings are added only when connection is inserted into tree */
	u_char *srch;   /* Hostname of source IPv4 address (if resolve) */
	u_char *dsth; 	/* Hostname of destination IPv4 address (if resolve) */
	u_char *scka;	/* "src:srcp <-> dst:dstp" */
};


/* Three way hanshake flags */
#define CONN_SYN_SENT			0x001
#define	CONN_SYN_ACK_SENT		0x002
#define	CONN_ACK_SENT			0x004
#define CONN_ESTABLISHED    	0x008
#define CONN_FIN_FROM_SRC   	0x010
#define CONN_FIN_FROM_DST   	0x020
#define	CONN_SOURCE_FINISHED	0x040
#define	CONN_DEST_FINISHED		0x080
#define	CONN_FINISHED			0x100
/* Connection was initiated before startup */
#define	CONN_GRABBED			0x200

/* Number of ACK packets required before printing a grabbed connection */
#define CONN_GRABBED_ACKS		3

/* Is there a FIN packet in some direction ? */
#define HASFIN(conn)	(((conn)->twh & CONN_FIN_FROM_SRC) || ((conn)->twh & CONN_FIN_FROM_DST))

/* Number of seconds for a connection to become idle */
#define	CONN_SEC_IDLE			20
#define AGEINSEC(conn)          (time(NULL) - (conn)->lupd)
#define ISIDLE(conn)			(AGEINSEC(conn) >= CONN_SEC_IDLE)
#define IDLEAGESEC(conn)		(ISIDLE(conn) ? (AGEINSEC(conn)-CONN_SEC_IDLE) : 0)


/* Test if connection is printable 
 * Require three way handshake or CONN_GRABBED_ACKS ack packets
 * for spotted connections */
#define CONN_DISPLAY(conn) \
	  (((conn)->twh & CONN_GRABBED) ? (((conn)->ackp >= CONN_GRABBED_ACKS) && (ISIDLE(conn)?opt.idle:1)) :  \
	  (!((conn)->twh & CONN_ESTABLISHED)?0: \
	  (ISIDLE(conn)?opt.idle:1)))

/* Free connection memory */
#define FREE_CONN_MEM(conn)         \
	{                               \
     if ((conn).srch != NULL)       \
	 	free((conn).srch);          \
	 if ((conn).dsth != NULL)       \
	 	free((conn).dsth);          \
	 if ((conn).scka != NULL)       \
	 	free((conn).scka);          \
	}

/* Free connection structure */
#define FREE_CONN(conn)             \
	if (conn != NULL) {             \
		FREE_CONN_MEM(*(conn));     \
		free(conn);                 \
		conn = NULL;                \
	}

/* Free and unlink connection from list */
#define CONN_UNLINK(link)                      \
            if (link == first) {               \
				first = first->next;           \
				                               \
				if (first != NULL)             \
					first->prev = NULL;        \
            }                                  \
            else if (link == last) {           \
				last = last->prev;             \
                                               \
				if (last != NULL)              \
					last->next = NULL;         \
            }                                  \
            else {                             \
                link->prev->next = link->next; \
                link->next->prev = link->prev; \
            }                                  \
                                               \
            FREE_CONN(link->conn);             \
            free(link)

/* The connections */
struct conn_node {
	struct conn *conn;		/* The connection */
	struct conn_node *next;
	struct conn_node *prev;
};

/* conn.c */
extern void conn_manage(struct conn *, u_short);
extern const struct conn *conn_getarr(u_int *);
extern char *conn_sock2str(struct conn *);
extern int conn_cmp(const struct conn *, const struct conn *);
extern struct conn *conn_get(struct conn *, struct conn *);

#endif /* _CONNN_H */
