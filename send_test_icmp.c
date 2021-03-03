#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <unistd.h>

#define PKT_BUFLEN 128
#include "if_icmptun.h"

/*
 * Checksum routine for Internet Protocol family headers (C Version).
 *
 * Refer to "Computing the Internet Checksum" by R. Braden, D. Borman and
 * C. Partridge, Computer Communication Review, Vol. 19, No. 2, April 1989,
 * pp. 86-101, for additional details on computing this checksum.
 */

int			/* return checksum in low-order 16 bits */
in_cksum_priv(void *parg, int nbytes)
{
	u_short *ptr = parg;
	register long		sum;		/* assumes long == 32 bits */
	u_short			oddbyte;
	register u_short	answer;		/* assumes u_short == 16 bits */

	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */

	sum = 0;
	while (nbytes > 1)  {
		sum += *ptr++;
		nbytes -= 2;
	}

				/* mop up an odd byte, if necessary */
	if (nbytes == 1) {
		oddbyte = 0;		/* make sure top half is zero */
		*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
		sum += oddbyte;
	}

	/*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */

	sum  = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */
	return(answer);
}

const u_char *tstpkt =
    "\x45\x00\x00\x2e\x2b\x6d\x40\x00\x40\x01\x96\x69\xac\x10\x10\x41" \
    "\xac\x10\x10\x97\x08\x00\xbb\x36\xca\xfe\x42\x43\x42\xca\xde\xad" \
    "\x9b\x96\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19";

const u_char *tstpkt2 =
    "\x45\x10\x00\x3c\x5d\x2a\x40\x00\x40\x06\x64\x89\xac\x10\x10\x41" \
    "\xac\x10\x10\x97\xa7\x70\x00\x17\xf0\x03\x7d\xba\x00\x00\x00\x00" \
    "\xa0\x02\xfa\xf0\x79\x27\x00\x00\x02\x04\x05\xb4\x04\x02\x08\x0a"
    "\x50\x70\x7a\xae\x00\x00\x00\x00\x01\x03\x03\x0a";


int main(int argc, const char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "%s [dst ip] [tunkey]\n", argv[0]);
        return 1;
    }
    
    struct sockaddr_in dst_addr;
    bzero(&dst_addr, sizeof(struct sockaddr_in));
    inet_pton(AF_INET, argv[1], &dst_addr.sin_addr);
    dst_addr.sin_family = AF_INET;

    int tunkey = atoi(argv[2]);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0)
    {
        perror("socket");
        return 1;
    }
    
    u_char pktbuf[PKT_BUFLEN];
    for (u_char i = 0; i < PKT_BUFLEN; i++)
        pktbuf[i] = 0;

    struct icmptun *icmptunh = (struct icmptun *) pktbuf;
    icmptunh->ic_type = 8;
    icmptunh->ic_code = 0;
    icmptunh->ic_cksum = 0;
    icmptunh->ic_ident = htons(tunkey);
    icmptunh->ic_seq = htons(0x4243);

    icmptunh->tun_ver = ICMPTUN_VERSION;
    icmptunh->tun_flags = 0xca;
    icmptunh->tun_proto = htons(4);

    size_t datalen = 60;
    u_char *data = pktbuf + sizeof(struct icmptun);
    memcpy(data, tstpkt2, datalen);
    icmptunh->tun_cksum = in_cksum_priv(data, datalen);

    size_t sz = sizeof(struct icmptun) + datalen;
    icmptunh->ic_cksum = in_cksum_priv(pktbuf, sz);
    
    int err;
    err = sendto(s, pktbuf, sz, 0, (struct sockaddr *)&dst_addr,
        sizeof(struct sockaddr) );

    if (err < 0)
    {
        perror("sendto");
        return 1;
    }
    
    close(s);
    return 0;
}
