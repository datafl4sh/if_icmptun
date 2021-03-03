#ifndef _NET_IF_ICMPTUN_H_
#define _NET_IF_ICMPTUN_H_

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

#define ICMPTUN_VERSION     0x42

#ifdef _KERNEL

struct ip;
struct ip6_hdr;

struct icmptun_softc {
	struct ifnet    *icmptun_ifp;
	int			    icmptun_family;
	u_int			icmptun_fibnum;
	u_int			icmptun_hlen;
	u_short         icmptun_key;
	union {
		void		    *hdr;
		struct ip       *iphdr;
		struct ip6_hdr	*ip6hdr;
	} icmptun_uhdr;

	CK_LIST_ENTRY(icmptun_softc) chain;
	CK_LIST_ENTRY(icmptun_softc) srchash;
};
CK_LIST_HEAD(icmptun_list, icmptun_softc);
MALLOC_DECLARE(M_ICMPTUN);

#define	ICMPTUN2IFP(sc)	((sc)->icmptun_ifp)
#define	icmptun_hdr		icmptun_uhdr.hdr
#define	icmptun_iphdr	icmptun_uhdr.iphdr
#define	icmptun_ip6hdr	icmptun_uhdr.ip6hdr

#define	ICMPTUN_WAIT() epoch_wait_preempt(net_epoch_preempt)

#define	GREGKEY		_IOWR('i', 107, struct ifreq)
#define	GRESKEY	    _IOW('i', 108, struct ifreq)

int     in_icmptun_ioctl(struct icmptun_softc *, u_long, caddr_t);
void    icmptun_input(struct mbuf *, int, int, void *);

#endif /* _KERNEL */

#endif /* _NET_IF_ICMPTUN_H_ */
