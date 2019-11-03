/*
 *  zniper.h  - zniper header file
 *
 *  Copyright (c) 2002 Claes M. Nyberg <cmn@fuzzpoint.com>
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
 * $Id: zniper.h,v 1.1.1.1 2004-07-30 11:19:33 cmn Exp $
 */ 

#ifndef _ZNIPER_H
#define _ZNIPER_H

#include <sys/types.h>
#include "version.h"
#include "log.h"
#include "twin.h"
#include "iact.h"
#include "iraw.h"
#include "net.h"
#include "conn.h"
#include "utils.h"


/* Ways to sort connections */
#define SORT_TIME_DESC		1
#define SORT_TIME       	2
#define SORT_SRC_DESC		3
#define SORT_SRC         	4
#define SORT_DST_DESC       5
#define SORT_DST            6
#define SORT_SRCP_DESC		7
#define SORT_SRCP			8
#define SORT_DSTP_DESC		9
#define SORT_DSTP		   10


/*
 * Global options
 */
struct options {
    short bgc;       /* Background color */
    short fgc;       /* Foreground color */
    short boc;       /* Border color */
	u_char usec:1;   /* Use colors */
    u_char conhp;    /* Height of connection window in percent */
    u_short conhl;   /* Height of connection window in lines */
	u_short sortby;  /* How to sort the connections */ 
	u_char *logfile; 

	int sock_raw;      /* The raw socket for sending packets */
	u_char verbose;    /* Verbose level */
	u_char *iface;     /* Network interface */
	u_char promisc:1;  /* Promiscous mode */
	u_char resolve:1;  /* Resolve hostnames */
	u_char grab:1;     /* Attempt to grab allready established connections */

	u_char statw:1;		/* Display status window */
	u_char idle:1;		/* Display idle connections */
};


/* sniff.c */
extern void *sniff(void *);


#endif /* _ZNIPER_H */
