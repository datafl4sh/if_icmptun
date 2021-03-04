/*-
 * IP-over-ICMP tunnel interface.
 *
 * Matteo `datafl4sh` Cicuttin (C) 2021.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NET_IF_ICMPTUN_H_
#define _NET_IF_ICMPTUN_H_

/* This is the ICMPTUN packet header. The first part consists in the standard
 * fields found in the ICMP ECHO and ICMP ECHOREPLY packets, the second part
 * is the data related to the actual ICMPTUN protocol.
 *
 *  tun_ver:        Protocol version, currently 0x42
 *  tun_flags:      One byte of flags, currently unused
 *  tun_proto:      Protocol encapsulated into the packets
 *  tun_cksum:      Checksum _of the payload_. This is used to determine
 *                  if we're dealing with an actual ICMPTUN packet or with
 *                  some other stuff.
 */
struct icmptun {
	/* ICMP header data */
	u_char      ic_type;
	u_char      ic_code;
	u_short     ic_cksum;
	u_short     ic_ident;
	u_short     ic_seq;
	/* ICMPTUN data */
	u_char      tun_ver;
	u_char      tun_flags;
	u_short     tun_proto;
	u_short     tun_cksum;
	u_short     tun_pad;
};

#define ICMPTUN_VERSION			0x42
#define	ICMPTUN_MTU				1464
#define ICMPTUNS_MAX			65536
#define ICMPTUN_TTL				30
#define ICMPTUN_ECHO_PADDING	0xDEAD


#ifdef _KERNEL

#define ICMPTUNPRINTFS

struct ip;
struct ip6_hdr;

struct icmptunip {
	struct ip       tun_ip;
	struct icmptun  tun_icmptun;
};

struct icmptun_softc {
	struct ifnet	*icmptun_ifp;
	int				icmptun_family;
	u_int			icmptun_fibnum;
	u_int			icmptun_hlen;
	u_short			icmptun_ident;
	u_short			icmptun_pktype;
	union {
		struct ip       *iphdr;
		struct ip6_hdr	*ip6hdr;
	} icmptun_uhdr;

	CK_LIST_ENTRY(icmptun_softc) chain;
	CK_LIST_ENTRY(icmptun_softc) srchash;
};
CK_LIST_HEAD(icmptun_list, icmptun_softc);
MALLOC_DECLARE(M_ICMPTUN);

#define	ICMPTUN2IFP(sc)	((sc)->icmptun_ifp)
#define	icmptun_iphdr	icmptun_uhdr.iphdr
#define	icmptun_ip6hdr	icmptun_uhdr.ip6hdr

#define	ICMPTUN_RLOCK()		struct epoch_tracker gif_et; epoch_enter_preempt(net_epoch_preempt, &gif_et)
#define	ICMPTUN_RUNLOCK()	epoch_exit_preempt(net_epoch_preempt, &gif_et)
#define	ICMPTUN_WAIT() 		epoch_wait_preempt(net_epoch_preempt)

#define	GREGKEY		_IOWR('i', 107, struct ifreq)
#define	GRESKEY		_IOW('i', 108, struct ifreq)

int     icmptun_input(struct mbuf *, int, int, void *);
int     in_icmptun_ioctl(struct icmptun_softc *, u_long, caddr_t);
int     in_icmptun_output(struct ifnet *, struct mbuf *, int, uint8_t);

#endif /* _KERNEL */

#endif /* _NET_IF_ICMPTUN_H_ */
