/*
 *  log.c
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
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include "zniper.h"


/* Global variables */
extern struct options opt;

/* Private variables */
static FILE *logfile;

/*
 * Open log file
 * Returns zero on success, -1 on error.
 */
int
log_open(const char *file)
{
	if (logfile != NULL)
		fclose(logfile);
	
	if ( (logfile = fopen(file, "w+b")) == NULL) {
		fprintf(stderr, "Error: Failed to open logfile: %s\n", 
			strerror(errno));
		return(-1);
	}
	
	return(0);
}


/*
 * Write to logfile if verbose level is high enough
 */
void
log_write(u_char level, const char *fmt, ...)
{
	va_list ap;

	if ((logfile != NULL) && (level <= opt.verbose)) {
		fprintf(logfile, "[%s] ", timestr(time(NULL)));
		va_start(ap, fmt);
		vfprintf(logfile, fmt, ap);
		va_end(ap);
		fflush(logfile);
	}
}
