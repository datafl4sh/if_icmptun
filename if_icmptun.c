#include <sys/cdefs.h>

//#include "opt_inet.h"
//#include "opt_inet6.h"
//#include "opt_rss.h"

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
#include <sys/epoch.h>


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

#define	ICMPTUNMTU      1000

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

#define ICMPTUNS_MAX    65536
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
    //struct icmp *icp;
    struct mbuf *m = *mp;
    struct ip *iph = mtod(m, struct ip *);
    struct icmptun *itp;
    struct ifnet *ifp;
    int hlen = *offp;
    int icmplen = ntohs(iph->ip_len) - *offp;
    int ihlen = hlen + sizeof(struct icmptun);
    int icmptunlen = ntohs(iph->ip_len) - ihlen;
    int i;
    u_short csum, tun_key;
    
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
    
#if 0
    struct ifnet *ifp = m->m_pkthdr.rcvif;
    if (ifp == NULL)
    {
        /* This probably should never happen, but if it happens
         * let the default icmp_input() handle it.*/
        printf("ifnet is null\n");
        goto dfl;
    }
    else
    {
        printf("ifnet.if_xname = %s\n", ifp->if_xname);
    }
#endif
    
    printf("received icmp type %d code %d\n", itp->ic_type, itp->ic_code);
    if (itp->ic_type == ICMP_ECHO)
    {
        u_short id = ntohs(itp->ic_ident);
        u_short seq = ntohs(itp->ic_seq);
        u_short iplen = ntohs(iph->ip_len);
        printf("id: %d, seq: %d, ip_len: %d, icmplen: %d\n", id, seq, iplen, icmplen);
    }
    hexdump(m->m_data, m->m_len, NULL, 0);
    
    switch(itp->ic_type)
    {
        case ICMP_ECHOREPLY:
        case ICMP_ECHO:

            if (m->m_len < ihlen) {
                printf("short, goto dfl: %d %d\n", m->m_len, ihlen);
                goto dfl;
            }
            
            if (itp->tun_ver != ICMPTUN_VERSION) {
                printf("unexpected version 0x%x, goto dfl\n", itp->tun_ver);
                goto dfl;
            }

            m->m_len -= ihlen;
            m->m_data += ihlen;
            csum = in_cksum(m, icmptunlen);
            m->m_len += ihlen;
            m->m_data -= ihlen;
            
            if (csum != itp->tun_cksum) {
                printf("invalid payload checksum, goto dfl\n");
                goto dfl;
            }
            
            /* OK, we're good here. Handle the encapsulated packet to
             * the upper protocol layers. */
            
            tun_key = ntohs(itp->ic_ident);
            ifp = icmptun_ifp[tun_key];
            if (ifp == NULL) {
                printf("No interface assigned to ident %d\n", tun_key);
                goto freeit;
            }
            
            if (ifp == m->m_pkthdr.rcvif) {
                printf("Same interface, goto dfl\n");
                goto dfl;
            }
            
            icmptun_input(m, ihlen, htons(itp->tun_proto), ifp);
            return (IPPROTO_DONE);
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

	ICMPTUN2IFP(sc)->if_mtu = ICMPTUNMTU;
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
	u_short tun_key;
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
		    error = EINVAL;//in6_gre_ioctl(sc, cmd, data);
		    break;
		    
		case SIOCGTUNFIB:
		    ifr->ifr_fib = sc->icmptun_fibnum;
		    break;
	    
	    case SIOCSTUNFIB:
		    //if ((error = priv_check(curthread, PRIV_NET_GRE)) != 0)
			//    break;
		    if (ifr->ifr_fib >= rt_numfibs)
			    error = EINVAL;
		    else
			    sc->icmptun_fibnum = ifr->ifr_fib;
            break;

        case GRESKEY:
            if ((error = copyin(ifr_data_get_ptr(ifr), &opt, sizeof(opt))) != 0)
                break;
            
            tun_key = (opt & 0xFFFF);
            if ( icmptun_ifp[ tun_key ] != NULL ) {
                printf("Key %d already in use by another tunnel\n", tun_key);
                error = EINVAL;
                break;
            }

            icmptun_ifp[ sc->icmptun_key ] = NULL;
            sc->icmptun_key = tun_key;
            icmptun_ifp[ sc->icmptun_key ] = ifp;
            printf("ifnet.if_xname = %s\n", ifp->if_xname);
            break;
            
        case GREGKEY:
            opt = sc->icmptun_key;
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
    return 0;
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

void
icmptun_input(struct mbuf *m, int off, int proto, void *arg)
{
	//struct ip *ip;
	//struct ip6_hdr *ip6;
	//uint32_t t;
	
	struct ifnet *ifp = arg;
	
	int isr, af;

    //NET_EPOCH_ASSERT();

	if (ifp == NULL) {
	    printf("ifp is NULL\n");
		m_freem(m);
		return;
    }
    
    m_adj(m, off);
    m->m_pkthdr.rcvif = ifp;
    m_clrprotoflags(m);
    switch (proto) {
        case IPPROTO_IPV4:
            printf("IPPROTO_IPV4 -> AF_INET\n");
            af = AF_INET;
            break;
            
        case IPPROTO_IPV6:
            printf("IPPROTO_IPV6 -> AF_INET6\n");
            af = AF_INET6;
            break;
            
        default:
            printf("invalid proto %d, dropping\n", proto);
            m_freem(m);
            goto drop;
    }
    
    switch (af) {
	    case AF_INET:
	        printf("AF_INET -> NETISR_IP\n");
		    isr = NETISR_IP;
		    break;

	    case AF_INET6:
		    isr = NETISR_IPV6;
		    printf("AF_INET6 -> NETISR_IPV6\n");
    		break;
    		
    	default:
    	    printf("invalid af, dropping\n");
    	    m_freem(m);
    	    return;
    }

    BPF_MTAP2(ifp, &af, sizeof(af), m);
    if_inc_counter(ifp, IFCOUNTER_IPACKETS, 1);
	if_inc_counter(ifp, IFCOUNTER_IBYTES, m->m_pkthdr.len);
	M_SETFIB(m, ifp->if_fib);
	netisr_dispatch(isr, m);
	return;

drop:
    if_inc_counter(ifp, IFCOUNTER_IERRORS, 1);
}

static moduledata_t icmptun_mod = {
	"if_icmptun",
	icmptun_modevent,
	0
};

DECLARE_MODULE(if_icmptun, icmptun_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(if_icmptun, 1);


