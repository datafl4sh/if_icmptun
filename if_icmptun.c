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
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mbuf.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/protosw.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_clone.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/vnet.h>
#include <net/route.h>


#include <netinet/in.h>
#include <netinet/in_pcb.h>
//#ifdef INET
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
//#endif

#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>

//#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
//#endif

#include <netinet/ip_encap.h>
#include <netinet/udp.h>
#include <net/bpf.h>
#include <net/netisr.h>

#include <machine/in_cksum.h>
#include <security/mac/mac_framework.h>

#include "if_icmptun.h"

static const char icmptunname[] = "icmptun";
MALLOC_DEFINE(M_ICMPTUN, icmptunname, "IP over ICMP Tunnel");

static struct sx icmptun_ioctl_sx;
SX_SYSINIT(icmptun_ioctl_sx, &icmptun_ioctl_sx, "icmptun_ioctl");

static int	icmptun_clone_create(struct if_clone *, int, caddr_t);
static void	icmptun_clone_destroy(struct ifnet *);
VNET_DEFINE_STATIC(struct if_clone *, icmptun_cloner);
#define	V_icmptun_cloner	VNET(icmptun_cloner)

static void	icmptun_qflush(struct ifnet *);
static int	icmptun_transmit(struct ifnet *, struct mbuf *);
static int	icmptun_ioctl(struct ifnet *, u_long, caddr_t);
static int	icmptun_output(struct ifnet *, struct mbuf *,
			const struct sockaddr *, struct route *);
static void	icmptun_delete_tunnel(struct icmptun_softc *);

extern struct protosw inetsw[];

static struct ifnet *icmptun_ifp[ICMPTUNS_MAX];

static void
vnet_icmptun_init(const void *unused __unused)
{

	V_icmptun_cloner = if_clone_simple(icmptunname, icmptun_clone_create,
		icmptun_clone_destroy, 0);
#ifdef INET
	//in_gre_init();
#endif
#ifdef INET6
	//in6_gre_init();
#endif
}
VNET_SYSINIT(vnet_icmptun_init, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY,
	vnet_icmptun_init, NULL);

static void
vnet_icmptun_uninit(const void *unused __unused)
{

	if_clone_detach(V_icmptun_cloner);
#ifdef INET
	//in_gre_uninit();
#endif
#ifdef INET6
	//in6_gre_uninit();
#endif
	/* XXX: epoch_call drain */
}
VNET_SYSUNINIT(vnet_icmptun_uninit, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY,
	vnet_icmptun_uninit, NULL);

static int
icmp_input_hook(struct mbuf **mp, int *offp, int proto)
{
	/* Here we determine if the packet is an actual ICMPTUN packet or if
	 * it is plain ICMP. In the former case the packet is passed to
	 * icmptun_input(), in the latter case the control is handed back to the
	 * operating system ICMP processing facilities */

	struct mbuf *m = *mp;
	struct ip *iph = mtod(m, struct ip *);
	struct icmptun *itp;
	struct ifnet *ifp;
	int hlen = *offp;
	int icmplen = ntohs(iph->ip_len) - *offp;
	int ihlen = hlen + sizeof(struct icmptun);
	int icmptunlen = ntohs(iph->ip_len) - ihlen;
	int i;
	u_short csum, tun_ident;
	
	/* Do standart ICMP validation, copy-paste from icmp_input() in
	 * netinet/ip_icmp.c */
	if (icmplen < ICMP_MINLEN) {
		//ICMPSTAT_INC(icps_tooshort);
		goto freeit;
	}
	
	i = hlen + min(icmplen, ICMP_ADVLENMIN);
	if (m->m_len < i && (m = m_pullup(m, i)) == NULL)  {
		//ICMPSTAT_INC(icps_tooshort);
		return (IPPROTO_DONE);
	}

	iph = mtod(m, struct ip *);
	m->m_len -= hlen;
	m->m_data += hlen;
	itp = mtod(m, struct icmptun *);
	if (in_cksum(m, icmplen)) {
		//ICMPSTAT_INC(icps_checksum);
		goto freeit;
	}
	m->m_len += hlen;
	m->m_data -= hlen;
	
	switch(itp->ic_type)
	{
		case ICMP_ECHOREPLY:
		case ICMP_ECHO:

			if (m->m_len < ihlen) {
				/* Insufficient data to be an ICMPTUN header, do standard
				 * ICMP processing */
				printf("short, goto dfl: %d %d\n", m->m_len, ihlen);
				goto dfl;
			}
			
			if (itp->tun_ver != ICMPTUN_VERSION) {
				/* Wrong protocol version, do standard ICMP processing */
				printf("unexpected version 0x%x, goto dfl\n", itp->tun_ver);
				goto dfl;
			}

			/* We got the correct version, assume it is an ICMPTUN packet
			 * and checksum the payload to determine if it actually is. */
			m->m_len -= ihlen;
			m->m_data += ihlen;
			csum = in_cksum(m, icmptunlen);
			m->m_len += ihlen;
			m->m_data -= ihlen;
			
			if (csum != itp->tun_cksum) {
				/* Invalid checksum, do standard ICMP processing */
				printf("invalid payload checksum, goto dfl\n");
				goto dfl;
			}
			
			/* Echo requests are padded with ICMPTUN_ECHO_PADDING whereas
			 * echo replies are padded with zeros. If we receive a reply
			 * padded with ICMPTUN_ECHO_PADDING the remote is just replying
			 * to pings and likely not configured. */
			if ( (itp->ic_type == ICMP_ECHOREPLY) &&
				 (itp->tun_pad == htons(ICMPTUN_ECHO_PADDING) ) ) {
				printf("remote probably not configured\n");
				goto freeit;
			}

			/* OK, we're good here, we got ICMPTUN data. Extract the tunnel
			 * key and send the payload to the correct interface. */
			tun_ident = ntohs(itp->ic_ident);
			ifp = icmptun_ifp[tun_ident];
			if (ifp == NULL) {
				printf("no interface assigned to ident%d\n", tun_ident);
				goto freeit;
			}
			
			return icmptun_input(m, ihlen, htons(itp->tun_proto), ifp);
			break;

		default:
			goto dfl;
	}

dfl:
	return icmp_input(mp, offp, proto);

freeit:
	m_freem(m);
	return (IPPROTO_DONE);
}

static int
icmptun_clone_create(struct if_clone *ifc, int unit, caddr_t params)
{
	struct icmptun_softc *sc;

	sc = malloc(sizeof(struct icmptun_softc), M_ICMPTUN, M_WAITOK | M_ZERO);
	sc->icmptun_fibnum = curthread->td_proc->p_fibnum;
	ICMPTUN2IFP(sc) = if_alloc(IFT_TUNNEL);
	ICMPTUN2IFP(sc)->if_softc = sc;
	if_initname(ICMPTUN2IFP(sc), icmptunname, unit);

	ICMPTUN2IFP(sc)->if_mtu = ICMPTUN_MTU;
	ICMPTUN2IFP(sc)->if_flags = IFF_POINTOPOINT|IFF_MULTICAST;
	ICMPTUN2IFP(sc)->if_output = icmptun_output;
	ICMPTUN2IFP(sc)->if_ioctl = icmptun_ioctl;
	ICMPTUN2IFP(sc)->if_transmit = icmptun_transmit;
	ICMPTUN2IFP(sc)->if_qflush = icmptun_qflush;
	ICMPTUN2IFP(sc)->if_capabilities |= IFCAP_LINKSTATE;
	ICMPTUN2IFP(sc)->if_capenable |= IFCAP_LINKSTATE;
	if_attach(ICMPTUN2IFP(sc));
	bpfattach(ICMPTUN2IFP(sc), DLT_NULL, sizeof(u_int32_t));
	return (0);
}

static void
icmptun_clone_destroy(struct ifnet *ifp)
{
	struct icmptun_softc *sc;

	sx_xlock(&icmptun_ioctl_sx);
	sc = ifp->if_softc;
	//gre_delete_tunnel(sc);
	bpfdetach(ifp);
	if_detach(ifp);
	ifp->if_softc = NULL;
	sx_xunlock(&icmptun_ioctl_sx);

	ICMPTUN_WAIT();
	if_free(ifp);
	free(sc, M_ICMPTUN);
}

static int
icmptun_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifreq *ifr = (struct ifreq *)data;
	struct icmptun_softc *sc;
	uint32_t opt;
	u_short tun_ident;
	int error;
	
	switch (cmd) {
		case SIOCSIFMTU:
			if (ifr->ifr_mtu < 576)
				return (EINVAL);
			ifp->if_mtu = ifr->ifr_mtu;
			return (0);
		case SIOCSIFADDR:
			ifp->if_flags |= IFF_UP;
		case SIOCSIFFLAGS:
		case SIOCADDMULTI:
		case SIOCDELMULTI:
			return (0);
	}
	
	sx_xlock(&icmptun_ioctl_sx);
	sc = ifp->if_softc;
	if (sc == NULL) {
		error = ENXIO;
		goto end;
	}
	
	error = 0;
	switch (cmd) {
		case SIOCDIFPHYADDR:
			if (sc->icmptun_family == 0)
				break;
			//gre_delete_tunnel(sc);
			break;

		case SIOCSIFPHYADDR:
		case SIOCGIFPSRCADDR:
		case SIOCGIFPDSTADDR:
			error = in_icmptun_ioctl(sc, cmd, data);
			break;

		case SIOCSIFPHYADDR_IN6:
		case SIOCGIFPSRCADDR_IN6:
		case SIOCGIFPDSTADDR_IN6:
			error = EOPNOTSUPP;//in6_gre_ioctl(sc, cmd, data);
			break;
			
		case SIOCGTUNFIB:
			ifr->ifr_fib = sc->icmptun_fibnum;
			break;
		
		case SIOCSTUNFIB:
			if (ifr->ifr_fib >= rt_numfibs)
				error = EINVAL;
			else
				sc->icmptun_fibnum = ifr->ifr_fib;
			break;

		/* Here we are reusing the same ioctls of if_gre. In that
		 * way we can abuse ifconfig to set the tunnel identifier. */
		case GRESKEY:
			if ((error = copyin(ifr_data_get_ptr(ifr), &opt, sizeof(opt))) != 0)
				break;
			
			if (opt >= ICMPTUNS_MAX) {
				error = EINVAL;
				break;
			}
			
			tun_ident = (opt & 0xFFFF);
			if ( icmptun_ifp[ tun_ident ] != NULL ) {
				printf("%s: ioctl(): key %d already in use by another tunnel\n",
					ifp->if_xname, tun_ident);
				error = EINVAL;
				break;
			}

			icmptun_ifp[ sc->icmptun_ident ] = NULL;
			sc->icmptun_ident = tun_ident;
			icmptun_ifp[ sc->icmptun_ident ] = ifp;
			break;
			
		case GREGKEY:
			opt = sc->icmptun_ident;
			error = copyout(&opt, ifr_data_get_ptr(ifr), sizeof(opt));
			break;
			
		default:
			error = EINVAL;
			break;
	}

	if (error == 0)
	{
		if_link_state_change(ifp, LINK_STATE_UP);
	}

end:
	sx_xunlock(&icmptun_ioctl_sx);
	return (error);
}

static int
icmptun_output(struct ifnet *ifp, struct mbuf *m, const struct sockaddr *dst,
   struct route *ro)
{
	printf("%s\n", __FUNCTION__);
	uint32_t af;

	if (dst->sa_family == AF_UNSPEC)
		bcopy(dst->sa_data, &af, sizeof(af));
	else
		af = dst->sa_family;
	/*
	 * Now save the af in the inbound pkt csum data, this is a cheat since
	 * we are using the inbound csum_data field to carry the af over to
	 * the gre_transmit() routine, avoiding using yet another mtag.
	 */
	m->m_pkthdr.csum_data = af;
	return (ifp->if_transmit(ifp, m));
}

static int
icmptun_transmit(struct ifnet *ifp, struct mbuf *m)
{
	printf("%s\n", __FUNCTION__);
	
	ICMPTUN_RLOCK();
	uint32_t af = m->m_pkthdr.csum_data;
	BPF_MTAP2(ifp, &af, sizeof(af), m);
	
	in_icmptun_output(ifp, m, 0, 0);
	
	ICMPTUN_RUNLOCK();
	return 0;
}

int
icmptun_input(struct mbuf *m, int off, int proto, void *arg)
{
	struct ifnet *ifp = arg;
	
	int isr, af;

	if (ifp == NULL) {
		m_freem(m);
		return (IPPROTO_DONE);
	}
	
	m_adj(m, off);
	m->m_pkthdr.rcvif = ifp;
	m_clrprotoflags(m);
	switch (proto) {
		case IPPROTO_IPV4:
			printf("IPPROTO_IPV4 -> AF_INET\n");
			af = AF_INET;
			isr = NETISR_IP;
			break;
			
		case IPPROTO_IPV6:
			printf("IPPROTO_IPV6 -> AF_INET6\n");
			af = AF_INET6;
			isr = NETISR_IPV6;
			break;
			
		default:
			printf("invalid proto %d, dropping\n", proto);
			m_freem(m);
			goto drop;
	}

	BPF_MTAP2(ifp, &af, sizeof(af), m);
	if_inc_counter(ifp, IFCOUNTER_IPACKETS, 1);
	if_inc_counter(ifp, IFCOUNTER_IBYTES, m->m_pkthdr.len);
	M_SETFIB(m, ifp->if_fib);
	netisr_dispatch(isr, m);
	return (IPPROTO_DONE);

drop:
	if_inc_counter(ifp, IFCOUNTER_IERRORS, 1);
	return (IPPROTO_DONE);
}
static void
icmptun_qflush(struct ifnet *ifp __unused)
{}

static int
icmptun_modevent(module_t mod, int type, void *data)
{

	switch (type) {
		case MOD_LOAD:
			bzero(icmptun_ifp, ICMPTUNS_MAX*sizeof(struct ifnet *));
			inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input_hook;
			printf("if_icmptun driver loaded\n");
			break;

		case MOD_UNLOAD:
			inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
			printf("if_icmptun driver unloaded\n");
			break;
	
		default:
			return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t icmptun_mod = {
	"if_icmptun",
	icmptun_modevent,
	0
};

DECLARE_MODULE(if_icmptun, icmptun_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(if_icmptun, 1);


