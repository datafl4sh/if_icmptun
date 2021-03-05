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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/proc.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>
#include <netinet/ip_encap.h>
#include <netinet/ip_ecn.h>
#include <netinet/in_fib.h>

#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>

#ifdef INET6
#include <netinet/ip6.h>
#endif

#include <machine/in_cksum.h>

#include "if_icmptun.h"

static void
in_icmptun_set_running(struct icmptun_softc *sc)
{
	if (in_localip(sc->icmptun_iphdr->ip_src))
		ICMPTUN2IFP(sc)->if_drv_flags |= IFF_DRV_RUNNING;
	else
		ICMPTUN2IFP(sc)->if_drv_flags &= ~IFF_DRV_RUNNING;
}

int
in_icmptun_ioctl(struct icmptun_softc *sc, u_long cmd, caddr_t data)
{
	struct ifreq *ifr = (struct ifreq *)data;
	struct sockaddr_in *dst, *src;
	struct ip *ip;
	struct icmptun *icmptunh;
	int error;
	u_long sa, da;

	/* NOTE: we are protected with icmptun_ioctl_sx lock */
	error = EINVAL;
	switch (cmd) {
	case SIOCSIFPHYADDR:
		src = &((struct in_aliasreq *)data)->ifra_addr;
		dst = &((struct in_aliasreq *)data)->ifra_dstaddr;

		/* sanity checks */
		if (src->sin_family != dst->sin_family ||
			src->sin_family != AF_INET ||
			src->sin_len != dst->sin_len ||
			src->sin_len != sizeof(*src))
			break;
		if (src->sin_addr.s_addr == INADDR_ANY ||
			dst->sin_addr.s_addr == INADDR_ANY) {
			error = EADDRNOTAVAIL;
			break;
		}
		/*
		if (V_ipv4_hashtbl == NULL) {
			V_ipv4_hashtbl = gif_hashinit();
			V_ipv4_srchashtbl = gif_hashinit();
		}
		*/
		error = 0;//in_gif_checkdup(sc, src->sin_addr.s_addr, dst->sin_addr.s_addr);
		
		if (error == EADDRNOTAVAIL)
			break;
		if (error == EEXIST) {
			/* Addresses are the same. Just return. */
			error = 0;
			break;
		}
		ip = malloc(sizeof(struct ip), M_ICMPTUN, M_WAITOK | M_ZERO);
		ip->ip_src.s_addr = src->sin_addr.s_addr;
		ip->ip_dst.s_addr = dst->sin_addr.s_addr;
		if (sc->icmptun_family != 0) {
			/* Detach existing tunnel first */
			//CK_LIST_REMOVE(sc, srchash);
			//CK_LIST_REMOVE(sc, chain);
			ICMPTUN_WAIT();
			//free(sc->icmptun_hdr, M_ICMPTUN);
			/* XXX: should we notify about link state change? */
		}
		sc->icmptun_family = AF_INET;
		sc->icmptun_iphdr = ip;

		sa = src->sin_addr.s_addr;
		da = dst->sin_addr.s_addr;

		if (sa == da) {
			error = EADDRNOTAVAIL;
			break;
		}

		icmptunh = malloc(sizeof(struct icmptun), M_ICMPTUN,  M_WAITOK | M_ZERO);

		icmptunh->ic_code = 0;
		icmptunh->ic_ident = htons(sc->icmptun_ident);
		icmptunh->ic_seq = 0;
		icmptunh->tun_ver = ICMPTUN_VERSION;
		icmptunh->tun_flags = 0;
		icmptunh->tun_proto = htons(4);
	
		/* If we are the tunnel side with smaller address use ICMP_ECHO
		 * otherwise use ICMP_ECHOREPLY packets. */
		if (sa < da) {
			icmptunh->ic_type = ICMP_ECHO;
			icmptunh->tun_pad = htons(ICMPTUN_ECHO_PADDING);
		} else {
			icmptunh->ic_type = ICMP_ECHOREPLY;
			icmptunh->tun_pad = 0;
		}
		sc->icmptun_tunhdr = icmptunh;

		//in_gif_attach(sc);
		in_icmptun_set_running(sc);
		break;
	case SIOCGIFPSRCADDR:
	case SIOCGIFPDSTADDR:
		if (sc->icmptun_family != AF_INET) {
			error = EADDRNOTAVAIL;
			break;
		}
		src = (struct sockaddr_in *)&ifr->ifr_addr;
		memset(src, 0, sizeof(*src));
		src->sin_family = AF_INET;
		src->sin_len = sizeof(*src);
		src->sin_addr = (cmd == SIOCGIFPSRCADDR) ?
			sc->icmptun_iphdr->ip_src: sc->icmptun_iphdr->ip_dst;
		error = prison_if(curthread->td_ucred, (struct sockaddr *)src);
		if (error != 0)
			memset(src, 0, sizeof(*src));
		break;
	}
	return (error);
}

int
in_icmptun_output(struct ifnet *ifp, struct mbuf *m, int proto, uint8_t ecn)
{
	struct icmptun_softc *sc = ifp->if_softc;
	struct icmptunip *itih;
	int len;
	
	u_short payload_csum = in_cksum(m, m->m_pkthdr.len);

	/* prepend new IP and ICMPTUN headers */
	MPASS(in_epoch(net_epoch_preempt));
	len = sizeof(struct icmptunip);

	M_PREPEND(m, len, M_NOWAIT);
	if (m == NULL)
		return (ENOBUFS);

	itih = mtod(m, struct icmptunip *);

	MPASS(sc->icmptun_family == AF_INET);
	bcopy(sc->icmptun_iphdr, &itih->tun_ip, sizeof(struct ip));
	bcopy(sc->icmptun_tunhdr, &itih->tun_icmptun, sizeof(struct icmptun));

	itih->tun_icmptun.ic_ident = htons(sc->icmptun_ident);
	itih->tun_icmptun.ic_seq = sc->icmptun_seq++; /* This is trash (and it should be) */
	itih->tun_icmptun.ic_cksum = 0;

	itih->tun_icmptun.tun_cksum = payload_csum;

	itih->tun_icmptun.ic_cksum =
		in_cksum_skip(m, m->m_pkthdr.len, sizeof(struct ip));

	itih->tun_ip.ip_p = IPPROTO_ICMP;
	itih->tun_ip.ip_ttl = ICMPTUN_TTL;
	itih->tun_ip.ip_len = htons(m->m_pkthdr.len);
	itih->tun_ip.ip_tos = ecn;

	return (ip_output(m, NULL, NULL, 0, NULL, NULL));
}



