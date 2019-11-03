/*
 *  capture.c - zniper pcap routines.
 *
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pcap.h>
#include "zniper.h"

/* Global options */
extern struct options opt;


/*
 * Opens a device to capture packets from (NULL for lookup).
 * Returns a NULL pointer on error and a pointer
 * to a struct capture on success.
 * Arguments:
 *  dev     - Device to open (NULL for lookup)
 *  promisc - Should be one for open in promisc mode, 0 otherwise
 */
struct capture *
cap_open(u_char *dev, int promisc)
{
    u_char ebuf[PCAP_ERRBUF_SIZE];   /* Pcap error string */
    struct capture cap;
    struct capture *pt;

    /* Open file */
    if (is_reg_file(dev)) {

        if (file_size(dev) == 0) {
            fprintf(stderr, "Target file '%s' is empty\n", dev);
            return(NULL);
        }

        if ( (cap.cap_pcapd = pcap_open_offline(dev, ebuf)) == NULL) {
            fprintf(stderr, "%s\n", ebuf);
            return(NULL);
        }
    }
    /* Open device */
    else {

        /* Let pcap pick an interface to listen on */
        if (dev == NULL) {
            if ( (dev = pcap_lookupdev(ebuf)) == NULL) {
                fprintf(stderr, "%s\n", ebuf);
                return(NULL);
            }
        }

        /* Init pcap */
        if (pcap_lookupnet(dev, &cap.cap_net,
                &cap.cap_mask, ebuf) != 0)
            fprintf(stderr, "%s\n", ebuf);

        /* Open the interface */
        if ( (cap.cap_pcapd = pcap_open_live(dev,
                CAP_SNAPLEN, promisc, CAP_TIMEOUT, ebuf)) == NULL) {
            fprintf(stderr, "%s\n", ebuf);
            return(NULL);
        }
    }

    /* Set linklayer offset
     * Offsets gatheret from various places (Ethereal, ipfm, ..) */
    switch(pcap_datalink(cap.cap_pcapd)) {

        case DLT_EN10MB:
            cap.cap_offst = 14;
            break;

        case DLT_ARCNET:
            cap.cap_offst = 6;
            break;

#ifdef DLT_PPP_ETHER
        case DLT_PPP_ETHER:
            cap.cap_offst = 8;
            break;
#endif

        case DLT_NULL:
        case DLT_LOOP:
        case DLT_PPP:
        case DLT_C_HDLC:        /* BSD/OS Cisco HDLC */
        case DLT_PPP_SERIAL:    /* NetBSD sync/async serial PPP */
            cap.cap_offst = 4;
            break;

        case DLT_RAW:
            cap.cap_offst = 0;
            break;

        case DLT_SLIP:
            cap.cap_offst = 16;
            break;

        case DLT_SLIP_BSDOS:
        case DLT_PPP_BSDOS:
            cap.cap_offst = 24;
            break;

        case DLT_ATM_RFC1483:
            cap.cap_offst = 8;
            break;

        case DLT_IEEE802:
            cap.cap_offst = 22;
            break;

        case DLT_IEEE802_11:
            cap.cap_offst = 30;
            break;

        /* Linux ATM defines this */
        case DLT_ATM_CLIP:
            cap.cap_offst = 8;
            break;

#ifdef DLT_PRISM_HEADER
        case DLT_PRISM_HEADER:
            cap.cap_offst = 144+30;
            break;
#endif /* DLT_PRISM_HEADER */

        /* fake header for Linux cooked socket */
        case DLT_LINUX_SLL:
            cap.cap_offst = 16;
            break;

#ifdef DLT_LTALK
        case DLT_LTALK:
            cap.cap_offst = 0;
            break;
#endif

        default:
            fprintf(stderr, "Unknown datalink type (%d) received for iface %s\n",
                pcap_datalink(cap.cap_pcapd), dev);
            return(NULL);
    }

	
    pt = memordie(sizeof(struct capture));
    memcpy(pt, &cap, sizeof(struct capture));
    return(pt);
}

/*
 * Set capture filter.
 * Returns -1 on error and 0 on success.
 */
int
cap_setfilter(struct capture *cap, u_char *filter)
{
    struct bpf_program fp; /* Holds compiled program */

    /* Compile filter string into a program and optimize the code */
    if (pcap_compile(cap->cap_pcapd, &fp, filter, 1, cap->cap_net) == -1) {
        fprintf(stderr, "pcap_compile() error\n");
        return(-1);
    }

    /* Set filter */
    if (pcap_setfilter(cap->cap_pcapd, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter() error\n");
        return(-1);
    }

	pcap_freecode(&fp);
    return(1);
}


/*  
 * Close opened interface
 */
void
cap_close(struct capture *cap)
{
    pcap_close(cap->cap_pcapd);
    free(cap); 
}

