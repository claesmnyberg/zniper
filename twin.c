/*
 *  twin.c  - zniper ncurses routines
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

#include <ncurses.h>
#include <panel.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include "zniper.h"

/* Global variables */
extern struct options opt;
struct winframe wframe;

/* Write status window lock */
pthread_mutex_t writestat;

/* Local variables */
static struct screen screen;
static struct statline *stat_first = NULL;
static struct statline *stat_last = NULL;
static u_int statlines = 0;

/*
 * SIGWINCH handler
 */
void
sigwinch_handler(int signo)
{
	delwin(screen.cwin);
	delwin(screen.swin);
	endwin();
	refresh();
	if (initscreen() < 0) {
		log_write(0, "** Error: Failed to initialize screen\n");
		exit(EXIT_FAILURE);
	}
	drawscreen();
	signal(SIGWINCH, sigwinch_handler);
}

#if UNDEF
/*
 * Create a new panel, returns NULL on error
 */
PANEL *
mkpanel(int nlines, int ncols, int begin_y, int begin_x)
{
	WINDOW *win;
	PANEL *pan;

	if ( (win = newwin(nlines, ncols, 0, 0)) == NULL) {
		fprintf(stderr, "Error: Failed to create window\n");
		return(NULL);
	}

	if ( (pan = new_panel(win)) == NULL) {
		fprintf(stderr, "Error: Failed to create panel\n");
		delwin(win);
		return(NULL);
	}

	/* Move panel into position */
	if (begin_y || begin_x) {
		if (move_panel(pan, begin_y, begin_x) == ERR) {
			fprintf(stderr, "Error: Failed to move panel\n");
			del_panel(pan);
			delwin(win);
			return(NULL);
		}
	}

	return(pan);
}
#endif

/*
 * Initialize screen
 * Returns -1 on failure, 0 on success
 */
int
initscreen(void)
{
    /* Init library */
    if (initscr() == NULL)
		return(-1);

	if (opt.usec)
		opt.usec = has_colors();

    /* Enable color */
	if (opt.usec)
    	start_color();

    if (cbreak() == ERR)
		return(-1);

    /* Do not echo input */
    if (noecho() == ERR)
		return(-1);

    /* Don't do NL->CR/NL on output */
    if (nonl() == ERR)
		return(-1);

    /* Do not flush tty queue on interrupt */
	if (intrflush(stdscr, FALSE) == ERR)
		return(-1);

    /* enable keyboard mapping (arrows, function keys etc.) */
    if (keypad(stdscr, TRUE) == ERR)
		return(-1);

	/* Set up color */
	if (opt.usec) {
		init_pair(TEXT_COLOR_INDEX, opt.fgc, opt.bgc);
		init_pair(BORDER_COLOR_INDEX, opt.boc, opt.bgc);
	}

	/* Create windows */
	if (opt.statw) 
		opt.conhl = (u_short)ceil((opt.conhp/100.0)*LINES);
	else
		opt.conhl = LINES;
	
	if ((LINES-opt.conhl-2) < 1) {
		opt.conhl = LINES;
		opt.statw = 0;
	}

	screen.cwin = subwin(stdscr, opt.conhl, COLS, 0, 0);
	screen.clines = opt.conhl-2;
	screen.ccols = COLS-2;
	wframe.sindex = 0;
	wframe.eindex = opt.conhl-3;
	wframe.hindex = -1;
	leaveok(screen.cwin, TRUE);

	if (opt.statw) {
		screen.swin = subwin(stdscr, LINES-opt.conhl, COLS, opt.conhl, 0);	
		screen.slines = LINES-opt.conhl-2;
		screen.scols = COLS-2;
		leaveok(screen.swin, TRUE);
	}

	if ((screen.cwin == NULL) || (screen.swin == NULL))
		return(-1);

	signal(SIGWINCH, sigwinch_handler);
	return(0);
}

/*
 * Create connection line
 * Returns the number of characters written
 */
int
mkconnline(const struct conn *conn, char *buf, size_t len)
{
	size_t written;
	size_t addrlen;
	
    memset(buf, ' ', len-1);
    written = WININDENT;
	
	/* Handshake status */
	if (conn->twh & CONN_SOURCE_FINISHED)
		written += snprintf(&buf[written], len-(written+1), "F->");
	else if (conn->twh & CONN_DEST_FINISHED)
		written += snprintf(&buf[written], len-(written+1), "<-F");
	else if (conn->twh & CONN_GRABBED)
		written += snprintf(&buf[written], len-(written+1), "Old");
	else if (conn->twh & CONN_ESTABLISHED)
		written += snprintf(&buf[written], len-(written+1), "<->");
	else if (conn->twh & CONN_SYN_ACK_SENT)
		written += snprintf(&buf[written], len-(written+1), "<SA");
	else if (conn->twh & CONN_SYN_SENT)
		written += snprintf(&buf[written], len-(written+1), "S->");

	 /* Start time */
	written += snprintf(&buf[written], len-(written+1), " %s [%s]  ",
		ISIDLE(conn) ? "I" : " ", timestr(conn->start));
	
    addrlen = snprintf(&buf[written], len-(written+1), "%s:%u ",
    	net_ntoa(conn->cd.src, NULL), ntohs(conn->cd.srcp));

    /* Pad with spaces */
	buf[written+addrlen] = ' ';
    written += 22;

   	addrlen = snprintf(&buf[written], len-(written+1), "%s:%u",
    	net_ntoa(conn->cd.dst, NULL), ntohs(conn->cd.dstp));

    /* Pad with spaces */
	buf[written+addrlen] = ' ';	
    written += 21;

    if (opt.resolve && (*conn->srch != '\0')) {
    	written += snprintf(&buf[written], len-(written+1),
    		" (%s <-> %s)", conn->srch, conn->dsth);
	}

	buf[written] = ' ';
	buf[len-1] = '\0';
	return(written);
}

/*
 * Draw connection window
 */
void
drawconnwin(void)
{
	const struct conn *connarr;
	char buf[MAXWINLINE];
	u_int len;
	u_int y = 0;

	connarr = conn_getarr(&wframe.numconns);
	wclear(screen.cwin);

	if (wframe.hindex < 0) {
		wframe.sindex = 0;
		wframe.eindex = (wframe.numconns-1>(opt.conhl-3))?
				(opt.conhl-3): 
				(wframe.numconns-1);
	}
	else {
		if (wframe.hindex > (wframe.numconns-1)) 
			wframe.hindex = wframe.numconns-1;
		
		if (wframe.hindex > wframe.eindex) {
			wframe.eindex = wframe.hindex;
			wframe.sindex = wframe.eindex - (opt.conhl-3);
		}
		else if (wframe.hindex < wframe.sindex) {
			wframe.sindex = wframe.hindex;
			wframe.eindex = (wframe.numconns-1 > wframe.sindex+(opt.conhl-3)) ? 
					wframe.sindex+(opt.conhl-3) : 
					wframe.numconns-1;
		}
	}

	if ((wframe.sindex < 0) || (wframe.eindex < 0)) {
		wframe.sindex = 0;
		wframe.eindex = (wframe.numconns-1 > (opt.conhl-3)) ? 
				(opt.conhl-3) : 
				wframe.numconns-1;
	}

	/* Draw the lines/connections */
	if ((connarr != NULL) && (wframe.numconns > 0)) {
		
		if (opt.usec)
			wattrset(screen.cwin, 
				COLOR_PAIR(TEXT_COLOR_INDEX));	
		else 
			wattrset(screen.cwin, A_NORMAL);

		while ((wframe.sindex+y <= wframe.eindex+y) && 
				(connarr[wframe.sindex+y].lupd != 0)) {
			mkconnline(&connarr[wframe.sindex+y], buf, sizeof(buf));
			
			if (wframe.sindex+y == wframe.hindex) {
				memcpy(&wframe.hlconn.cd, &connarr[wframe.sindex+y].cd, 
					sizeof(wframe.hlconn.cd));
				wattrset(screen.cwin, A_REVERSE);
			}
			mvwaddnstr(screen.cwin, y+1, 1, buf, screen.ccols);

			if (wframe.sindex+y == wframe.hindex) {
				if (opt.usec)
					wattrset(screen.cwin, COLOR_PAIR(TEXT_COLOR_INDEX));
				else
					wattrset(screen.cwin, A_NORMAL);
			}
			y++;
		}
	}

	/* Draw border */
	if (opt.usec)
		wattrset(screen.cwin, COLOR_PAIR(BORDER_COLOR_INDEX));	
	box(screen.cwin, 0, 0);
	if (opt.usec) {
		wattrset(screen.cwin, COLOR_PAIR(TEXT_COLOR_INDEX));
		wattrset(screen.cwin, A_BOLD);
	}
	mvwaddstr(screen.cwin, 0, 5, " Connections ");

	len = snprintf(buf, sizeof(buf)-1, " (%u on %s, Idle: %s)", 
		wframe.numconns, opt.iface, opt.idle? "on": "off");

	mvwaddstr(screen.cwin, 0, COLS-(len+3), buf);
	wrefresh(screen.cwin);
}

/*
 * Draw status window
 */
void
drawstatuswin(void)
{
	struct statline *curr = stat_last;
	int y = screen.slines;

	if (opt.statw == 0)
		return;

	wclear(screen.swin);
	
    /* Draw the lines */
	if (opt.usec)
    	wattrset(screen.swin, COLOR_PAIR(TEXT_COLOR_INDEX));
	else
		wattrset(screen.cwin, A_NORMAL);
    while(y > 0 && curr != NULL) {
        mvwaddnstr(screen.swin, y, 1, curr->line, screen.scols);   
        curr = curr->prev;
        y--;
    }

	/* Draw border */
	if (opt.usec)
		wattrset(screen.swin, COLOR_PAIR(BORDER_COLOR_INDEX));
	box(screen.swin, 0, 0);
	if (opt.usec) {
		wattrset(screen.swin, COLOR_PAIR(TEXT_COLOR_INDEX));
		wattrset(screen.swin, A_BOLD);
	}
	mvwaddstr(screen.swin, 0, 5, " Status ");
	wrefresh(screen.swin);
}

/*
 * Draw the entire screen
 */
void
drawscreen(void)
{
	/* Clear the screen first */
	drawstatuswin();
	drawconnwin();
}

/*
 * Write string to status window if verbose is high enough
 */
void
writestatus(u_char level, const char *fmt, ...)
{
	struct statline *tmp;
	va_list ap;
	char buf[4096];

	if (level > opt.verbose)
		return;

	pthread_mutex_lock(&writestat);

	memset(buf, 0x00, sizeof(buf));
	memset(buf, ' ', WININDENT);
	va_start(ap, fmt);
	vsnprintf(&buf[WININDENT], sizeof(buf)-(WININDENT+1), fmt, ap);
	va_end(ap);

	if ( (tmp = (struct statline *)calloc(1,
			sizeof(struct statline))) == NULL) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}
	tmp->line = strdup(buf);
	
	/* First line */
	if (stat_first == NULL) {
		stat_first = tmp;
		stat_last = stat_first;
	}
	/* Maximum number of lines reached */
	else {
		if (statlines >= STATHIST) {
			struct statline *first;

			first = stat_first;
			stat_first = stat_first->next;
			stat_first->prev = NULL;
			free(first->line);
			free(first);
			statlines--;
		}

		/* Append the line */
		stat_last->next = tmp;
		stat_last->next->prev = stat_last;
		stat_last = stat_last->next;
	}
	
	/* Log to file */
	log_write(level, "%s\n", &buf[WININDENT]);

	statlines++;
	drawstatuswin();
	pthread_mutex_unlock(&writestat);
}
