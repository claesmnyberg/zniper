/*
 *  zniper.c  - zniper main file
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include "zniper.h"

/* Global variables */
struct options opt;

/* Locks */
extern pthread_mutex_t writestat;
extern pthread_mutex_t conn_tree;

void
cleanup(void)
{
	endwin();
}

void
usage(char *pname)
{
	printf("\nZniper - <pocpon@fuzzpoint.com>\n");
	printf("Usage: %s [Option(s)]\n", pname);
	printf("\n Options:\n");
	printf("  -b color   - Background color\n");
	printf("  -B color   - Border color\n");
	printf("  -f color   - Foreground color\n");
	printf("  -h         - This help\n");
	printf("  -i iface   - Network interface\n");
	printf("  -l file    - Log status information to file\n");
	printf("  -n         - Do not attempt to resolve hostnames\n");
	printf("  -p         - Do not put the interface in promiscuous mode\n");
	printf("  -s         - Require the initial SYN packet to display a connection\n");
	printf("  -v         - Verbose output, repeat to increase\n");
	printf("  -V         - Print \"%s\" and exit\n", VERSION);
	printf("\n");
}

int
get_color(char *str)
{
	if (!strcmp(str, "black"))
		return(COLOR_BLACK);
	else if (!strcmp(str, "red"))
		return(COLOR_RED);
	else if (!strcmp(str, "green"))
		return(COLOR_GREEN);
	else if (!strcmp(str, "yellow"))
		return(COLOR_YELLOW);
	else if (!strcmp(str, "blue"))
		return(COLOR_BLUE);
	else if (!strcmp(str, "magenta"))
		return(COLOR_MAGENTA);
	else if (!strcmp(str, "cyan"))
		return(COLOR_CYAN);
	else if (!strcmp(str, "white"))
		return(COLOR_WHITE);
	
	return(-1);
}

int
main(int argc, char *argv[])
{
	struct capture *cap;
	pthread_t sniff_thread;
	int flag;

	/* Default values */
	opt.bgc = COLOR_BLACK;
	opt.fgc = COLOR_WHITE;
	opt.boc = COLOR_GREEN;
	opt.conhp = 75;
	opt.promisc = 1;
	opt.sock_raw = -1;
	opt.resolve = 1;
	opt.grab = 1;
	opt.statw = 1;
	opt.idle = 1;
	opt.logfile = NULL;
	opt.usec = 1;

	while ( (flag = getopt(argc, argv, "f:b:B:l:i:nvVhps")) != -1) {
		switch(flag) {
				
			case 'b': opt.bgc = get_color(optarg); break;
			case 'B': opt.boc = get_color(optarg); break;
			case 'f': opt.fgc = get_color(optarg); break;
			case 'l':
				if (log_open(optarg) < 0)
					exit(EXIT_FAILURE);
				opt.logfile = optarg;
				break;
			
			case 's':
				opt.grab = 0;
				break;

			case 'h':
				usage(argv[0]);
				exit(EXIT_SUCCESS);
				break;
				
			case 'i':
				if (opt.iface != NULL)
					free(opt.iface);
				opt.iface = (u_char *)strdup(optarg);
				break;
			
			case 'n':
				opt.resolve = 0;
				break;
			
			case 'p':
				opt.promisc = 0;
				break;

			case 'v':
				opt.verbose++;
				break;

			case 'V':
				printf("%s\n", VERSION);
				exit(EXIT_SUCCESS);
				break;

			default:
				exit(EXIT_FAILURE);
		}
	}

	if (opt.bgc < 0 || opt.boc < 0 || opt.fgc < 0)
		opt.usec = 0;

	if (opt.verbose > 5)
		opt.verbose = 5;

	/* Open the raw socket to send packets from */
	if ( (opt.sock_raw = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("Error opening raw socket");
		exit(EXIT_FAILURE);
	}

	/* Open interface */
	if ( (cap = cap_open(opt.iface, opt.promisc)) == NULL)
		exit(EXIT_FAILURE);

	/* Filter out TCP packets */
	if (cap_setfilter(cap, "tcp") < 0)
		exit(EXIT_FAILURE);

	/* Revoke privs in case of setuid */
	seteuid(getuid());
	setuid(getuid());

	/* Create mutex objects */
	pthread_mutex_init(&writestat, NULL);
	pthread_mutex_init(&conn_tree, NULL);

	/* Set up screen */
    if (initscreen() < 0) {
		fprintf(stderr, "** Error: Failed to initialize screen\n");
		exit(EXIT_FAILURE);
	}
	drawscreen();

	writestatus(0, "Opened interface %s in %spromiscuous mode", 
		opt.iface, (opt.promisc == 1) ? "" : "non-");
	if (opt.logfile)
		writestatus(0, "Opened logfile %s", opt.logfile);
	writestatus(0, "Verbose level set to %d", opt.verbose);

	/* Create the sniff-thread */
	if (pthread_create(&sniff_thread, NULL, sniff, cap) != 0) {
		endwin();
		fprintf(stderr, "Error: Failed to create sniff thread\n");
		exit(EXIT_FAILURE);
	}

	atexit(cleanup);

	/* Enter interactive loop */
	iact();

	endwin();
	exit(EXIT_SUCCESS);
}
