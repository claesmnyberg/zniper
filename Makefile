#
#  File: Makefile
#  Author: Claes M. Nyberg <pocpon@fuzzpoint.com>
#  Description: zniper compiling rules.
#  Version: 1.0
#  Date: Mon Jan  5 13:46:15 CET 2004
#
#  Copyright (c) 2003 Claes M. Nyberg <pocpon@fuzzpoint.com>
#  All rights reserved, all wrongs reversed.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. The name of author may not be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
#  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
#  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# $Id: Makefile,v 1.2 2005-02-07 19:34:08 cmn Exp $
#

#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
SHELL       = /bin/sh
CC          = gcc
CFLAGS      = -g -Wall -O -I/usr/local/include -L/usr/local/lib
OBJS        = zniper.o twin.o log.o iact.o capture.o net.o sniff.o conn.o iraw.o\
              utils.o
MAN1_FILES  = zniper.1
PROG        = zniper
LIBS        = -lncurses -lm -lpcap
SUNLIBS     = -lsocket -lnsl

# Install path
# Root dir must end with '/' to avoid trouble ..
ROOT_DIR         = /usr/local/zniper/
BIN_DIR          = ${ROOT_DIR}usr/bin
MAN_DIR          = ${ROOT_DIR}usr/share/man
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#


none: fbsd_x86

new: clean fbsd_x86

all: ${PROG}

${PROG}: ${OBJS}
	${CC} ${CFLAGS} -o ${PROG} ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} ${PROG} *.core

netbsd_x86:
	@make all

linux_x86:
	@make LIBS='${LIBS} -lpthread' all

obsd_x86:
	@make CFLAGS='${CFLAGS} -DFIXIPLEN' LIBS='${LIBS} -pthread' all

fbsd_x86:
	@make LIBS='${LIBS} -pthread' all

macosx:
	@make CFLAGS='${CFLAGS} -DWORDS_BIGENDIAN' LIBS='${LIBS} -lpthread' all
	
solaris_sparc:
	@make CFLAGS='${CFLAGS} -DWORDS_BIGENDIAN' LIBS='${LIBS} ${SUNLIBS}' all

install:
	@strip ${PROG}
	@mkdir -p ${BIN_DIR}
	@strip ${PROG}
	@chmod 0755 ${BIN_DIR}
	@chown root:0 ${PROG} 
	@chmod 0555 ${PROG}
	cp -pi ${PROG} ${BIN_DIR}/${PROG}
	@mkdir -p ${MAN_DIR}/man1
	@chown root:0 ${MAN1_FILES} 
	@chmod 0444 ${MAN1_FILES} 
	cp -pi ${MAN1_FILES} ${MAN_DIR}/man1/

uninstall:
	rm -f ${BIN_DIR}/${PROG}
	PWD=`pwd`; cd ${MAN_DIR}/man1/; rm -f ${MAN1_FILES}; cd ${PWD}

run: all
	aterm -e ./${PROG} -l out -vvvvvvvvvvvvvvvvvvvvvvvvvv
