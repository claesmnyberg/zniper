/*
 *  twin.h  - Header file for zniper ncurses routines
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
 * $Id: twin.h,v 1.1.1.1 2004-07-30 11:19:33 cmn Exp $ 
 */ 

#ifndef _TWIN_H
#define _TWIN_H

#include <ncurses.h>
#include <panel.h>
#include <sys/types.h>
#include "conn.h"

#define TEXT_COLOR_INDEX 1
#define BORDER_COLOR_INDEX 2

/* Maximum length of line in window */
#define MAXWINLINE			2048

/* Number of status lines in history */
#define STATHIST			100

/* Space from left border */
#define WININDENT 			1

/*
 * The screen
 */
struct screen {
	WINDOW *cwin; /* Connection window */
	int clines;   /* Maximum visible lines in connection window */
	int ccols;    /* Maximum visible columns in connection window */
	WINDOW *swin; /* Status window */
	int slines;   /* Maximum visible lines in status window */
	int scols;    /* Maximum visible columns in status window */
};

/*
 * The frame of connections in connection window
 */
struct winframe {
	int sindex;		/* Start index */
	int eindex;		/* End index */
	int hindex;		/* Highlighted index */
	int numconns;
	struct conn hlconn;
};


/*
 * Status lines
 */
struct statline {
	char *line;
	struct statline *next;
	struct statline *prev;
};

/* twin.c */
extern int initscreen(void);
extern void drawscreen(void);
extern void writestatus(u_char, const char *, ...);
extern void drawconnwin(void);

#endif /* _TWIN_H */
