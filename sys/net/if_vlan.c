/*-
 * Copyright 1998 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/net/if_vlan.c,v 1.101 2006/03/09 14:42:51 ru Exp $
 */

/*
 * if_vlan.c - pseudo-device driver for IEEE 802.1Q virtual LANs.
 * Might be extended some day to also handle IEEE 802.1p priority
 * tagging.  This is sort of sneaky in the implementation, since
 * we need to pretend to be enough of an Ethernet implementation
 * to make arp work.  The way we do this is by telling everyone
 * that we are an Ethernet, and then catch the packets that
 * ether_output() left on our output queue when it calls
 * if_start(), rewrite them for use by the real outgoing interface,
 * and ask it to send them.
 */

#include "opt_inet.h"
#include "opt_vlan.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/rwlock.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_clone.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/if_ether.h>
#endif

#define VLANNAME	"vlan"
#define	VLAN_DEF_HWIDTH	4
#define	VLAN_IFFLAGS	(IFF_BROADCAST | IFF_MULTICAST)

LIST_HEAD(ifvlanhead, ifvlan);

struct ifvlantrunk {
	struct	ifnet   *parent;	/* parent interface of this trunk */
	struct	rwlock	rw;
#ifdef VLAN_ARRAY
	struct	ifvlan	*vlans[EVL_VLID_MASK+1]; /* static table */
#else
	struct	ifvlanhead *hash;	/* dynamic hash-list table */
	uint16_t	hmask;
	uint16_t	hwidth;
#endif
	int		refcnt;
	LIST_ENTRY(ifvlantrunk) trunk_entry;
};
static LIST_HEAD(, ifvlantrunk) trunk_list;

struct vlan_mc_entry {
	struct ether_addr		mc_addr;
	SLIST_ENTRY(vlan_mc_entry)	mc_entries;
};

struct	ifvlan {
	struct	ifvlantrunk *ifv_trunk;
	struct	ifnet *ifv_ifp;
#define	TRUNK(ifv)	((ifv)->ifv_trunk)
#define	PARENT(ifv)	((ifv)->ifv_trunk->parent)
	int	ifv_pflags;	/* special flags we have set on parent */
	struct	ifv_linkmib {
		int	ifvm_parent;
		int	ifvm_encaplen;	/* encapsulation length */
		int	ifvm_mtufudge;	/* MTU fudged by this much */
		int	ifvm_mintu;	/* min transmission unit */
		uint16_t ifvm_proto;	/* encapsulation ethertype */
		uint16_t ifvm_tag;	/* tag to apply on packets leaving if */
	}	ifv_mib;
	SLIST_HEAD(__vlan_mchead, vlan_mc_entry) vlan_mc_listhead;
	LIST_ENTRY(ifvlan) ifv_list;
};
#define	ifv_tag	ifv_mib.ifvm_tag
#define	ifv_encaplen	ifv_mib.ifvm_encaplen
#define	ifv_mtufudge	ifv_mib.ifvm_mtufudge
#define	ifv_mintu	ifv_mib.ifvm_mintu

/* Special flags we should propagate to parent. */
static struct {
	int flag;
	int (*func)(struct ifnet *, int);
} vlan_pflags[] = {
	{IFF_PROMISC, ifpromisc},
	{IFF_ALLMULTI, if_allmulti},
	{0, NULL}
};

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, IFT_L2VLAN, vlan, CTLFLAG_RW, 0, "IEEE 802.1Q VLAN");
SYSCTL_NODE(_net_link_vlan, PF_LINK, link, CTLFLAG_RW, 0, "for consistency");

static MALLOC_DEFINE(M_VLAN, VLANNAME, "802.1Q Virtual LAN Interface");

/*
 * We have a global mutex, that is used to serialize configuration
 * changes and isn't used in normal packet delivery.
 *
 * We also have a per-trunk rwlock, that is locked shared on packet
 * processing and exclusive when configuration is changed.
 *
 * The VLAN_ARRAY substitutes the dynamic hash with a static array
 * with 4096 entries. In theory this can give a boots in processing,
 * however on practice it does not. Probably this is because array
 * is too big to fit into CPU cache.
 */
static struct mtx ifv_mtx;
#define	VLAN_LOCK_INIT()	mtx_init(&ifv_mtx, "vlan_global", NULL, MTX_DEF)
#define	VLAN_LOCK_DESTROY()	mtx_destroy(&ifv_mtx)
#define	VLAN_LOCK_ASSERT()	mtx_assert(&ifv_mtx, MA_OWNED)
#define	VLAN_LOCK()		mtx_lock(&ifv_mtx)
#define	VLAN_UNLOCK()		mtx_unlock(&ifv_mtx)
#define	TRUNK_LOCK_INIT(trunk)	rw_init(&(trunk)->rw, VLANNAME)
#define	TRUNK_LOCK_DESTROY(trunk) rw_destroy(&(trunk)->rw)
#define	TRUNK_LOCK(trunk)	rw_wlock(&(trunk)->rw)
#define	TRUNK_UNLOCK(trunk)	rw_wunlock(&(trunk)->rw)
#define	TRUNK_LOCK_ASSERT(trunk) rw_assert(&(trunk)->rw, RA_WLOCKED)
#define	TRUNK_RLOCK(trunk)	rw_rlock(&(trunk)->rw)
#define	TRUNK_RUNLOCK(trunk)	rw_runlock(&(trunk)->rw)
#define	TRUNK_LOCK_RASSERT(trunk) rw_assert(&(trunk)->rw, RA_RLOCKED)

#ifndef VLAN_ARRAY
static	void vlan_inithash(struct ifvlantrunk *trunk);
static	void vlan_freehash(struct ifvlantrunk *trunk);
static	int vlan_inshash(struct ifvlantrunk *trunk, struct ifvlan *ifv);
static	int vlan_remhash(struct ifvlantrunk *trunk, struct ifvlan *ifv);
static	void vlan_growhash(struct ifvlantrunk *trunk, int howmuch);
static __inline struct ifvlan * vlan_gethash(struct ifvlantrunk *trunk,
	uint16_t tag);
#endif
static	void trunk_destroy(struct ifvlantrunk *trunk);

static	void vlan_start(struct ifnet *ifp);
static	void vlan_ifinit(void *foo);
static	void vlan_input(struct ifnet *ifp, struct mbuf *m);
static	int vlan_ioctl(struct ifnet *ifp, u_long cmd, caddr_t addr);
static	int vlan_setflag(struct ifnet *ifp, int flag, int status,
    int (*func)(struct ifnet *, int));
static	int vlan_setflags(struct ifnet *ifp, int status);
static	int vlan_setmulti(struct ifnet *ifp);
static	int vlan_unconfig(struct ifnet *ifp);
static	int vlan_config(struct ifvlan *ifv, struct ifnet *p, uint16_t tag);
static	void vlan_link_state(struct ifnet *ifp, int link);
static	void vlan_capabilities(struct ifvlan *ifv);
static	void vlan_trunk_capabilities(struct ifnet *ifp);

static	struct ifnet *vlan_clone_match_ethertag(struct if_clone *,
    const char *, int *);
static	int vlan_clone_match(struct if_clone *, const char *);
static	int vlan_clone_create(struct if_clone *, char *, size_t);
static	int vlan_clone_destroy(struct if_clone *, struct ifnet *);

static	struct if_clone vlan_cloner = IFC_CLONE_INITIALIZER(VLANNAME, NULL,
    IF_MAXUNIT, NULL, vlan_clone_match, vlan_clone_create, vlan_clone_destroy);

#ifndef VLAN_ARRAY
#define HASH(n, m)	((((n) >> 8) ^ ((n) >> 4) ^ (n)) & (m))
static void
vlan_inithash(struct ifvlantrunk *trunk)
{
	int i, n;
	
	/*
	 * The trunk must not be locked here since we call malloc(M_WAITOK).
	 * It is OK in case this function is called before the trunk struct
	 * gets hooked up and becomes visible from other threads.
	 */

	KASSERT(trunk->hwidth == 0 && trunk->hash == NULL,
	    ("%s: hash already initialized", __func__));

	trunk->hwidth = VLAN_DEF_HWIDTH;
	n = 1 << trunk->hwidth;
	trunk->hmask = n - 1;
	trunk->hash = malloc(sizeof(struct ifvlanhead) * n, M_VLAN, M_WAITOK);
	for (i = 0; i < n; i++)
		LIST_INIT(&trunk->hash[i]);
}

static void
vlan_freehash(struct ifvlantrunk *trunk)
{
#ifdef INVARIANTS
	int i;

	KASSERT(trunk->hwidth > 0, ("%s: hwidth not positive", __func__));
	for (i = 0; i < (1 << trunk->hwidth); i++)
		KASSERT(LIST_EMPTY(&trunk->hash[i]),
		    ("%s: hash table not empty", __func__));
#endif
	free(trunk->hash, M_VLAN);
	trunk->hash = NULL;
	trunk->hwidth = trunk->hmask = 0;
}

static int
vlan_inshash(struct ifvlantrunk *trunk, struct ifvlan *ifv)
{
	int i, b;
	struct ifvlan *ifv2;

	TRUNK_LOCK_ASSERT(trunk);
	KASSERT(trunk->hwidth > 0, ("%s: hwidth not positive", __func__));

	b = 1 << trunk->hwidth;
	i = HASH(ifv->ifv_tag, trunk->hmask);
	LIST_FOREACH(ifv2, &trunk->hash[i], ifv_list)
		if (ifv->ifv_tag == ifv2->ifv_tag)
			return (EEXIST);

	/*
	 * Grow the hash when the number of vlans exceeds half of the number of
	 * hash buckets squared. This will make the average linked-list length
	 * buckets/2.
	 */
	if (trunk->refcnt > (b * b) / 2) {
		vlan_growhash(trunk, 1);
		i = HASH(ifv->ifv_tag, trunk->hmask);
	}
	LIST_INSERT_HEAD(&trunk->hash[i], ifv, ifv_list);
	trunk->refcnt++;

	return (0);
}

static int
vlan_remhash(struct ifvlantrunk *trunk, struct ifvlan *ifv)
{
	int i, b;
	struct ifvlan *ifv2;

	TRUNK_LOCK_ASSERT(trunk);
	KASSERT(trunk->hwidth > 0, ("%s: hwidth not positive", __func__));
	
	b = 1 << trunk->hwidth;
	i = HASH(ifv->ifv_tag, trunk->hmask);
	LIST_FOREACH(ifv2, &trunk->hash[i], ifv_list)
		if (ifv2 == ifv) {
			trunk->refcnt--;
			LIST_REMOVE(ifv2, ifv_list);
			if (trunk->refcnt < (b * b) / 2)
				vlan_growhash(trunk, -1);
			return (0);
		}

	panic("%s: vlan not found\n", __func__);
	return (ENOENT); /*NOTREACHED*/
}

/*
 * Grow the hash larger or smaller if memory permits.
 */
static void
vlan_growhash(struct ifvlantrunk *trunk, int howmuch)
{

	struct ifvlan *ifv;
	struct ifvlanhead *hash2;
	int hwidth2, i, j, n, n2;

	TRUNK_LOCK_ASSERT(trunk);
	KASSERT(trunk->hwidth > 0, ("%s: hwidth not positive", __func__));

	if (howmuch == 0) {
		/* Harmless yet obvious coding error */
		printf("%s: howmuch is 0\n", __func__);
		return;
	}

	hwidth2 = trunk->hwidth + howmuch;
	n = 1 << trunk->hwidth;
	n2 = 1 << hwidth2;
	/* Do not shrink the table below the default */
	if (hwidth2 < VLAN_DEF_HWIDTH)
		return;

	/* M_NOWAIT because we're called with trunk mutex held */
	hash2 = malloc(sizeof(struct ifvlanhead) * n2, M_VLAN, M_NOWAIT);
	if (hash2 == NULL) {
		printf("%s: out of memory -- hash size not changed\n",
		    __func__);
		return;		/* We can live with the old hash table */
	}
	for (j = 0; j < n2; j++)
		LIST_INIT(&hash2[j]);
	for (i = 0; i < n; i++)
		while (!LIST_EMPTY(&trunk->hash[i])) {
			ifv = LIST_FIRST(&trunk->hash[i]);
			LIST_REMOVE(ifv, ifv_list);
			j = HASH(ifv->ifv_tag, n2 - 1);
			LIST_INSERT_HEAD(&hash2[j], ifv, ifv_list);
		}
	free(trunk->hash, M_VLAN);
	trunk->hash = hash2;
	trunk->hwidth = hwidth2;
	trunk->hmask = n2 - 1;
}

static __inline struct ifvlan *
vlan_gethash(struct ifvlantrunk *trunk, uint16_t tag)
{
	struct ifvlan *ifv;

	TRUNK_LOCK_RASSERT(trunk);

	LIST_FOREACH(ifv, &trunk->hash[HASH(tag, trunk->hmask)], ifv_list)
		if (ifv->ifv_tag == tag)
			return (ifv);
	return (NULL);
}

#if 0
/* Debugging code to view the hashtables. */
static void
vlan_dumphash(struct ifvlantrunk *trunk)
{
	int i;
	struct ifvlan *ifv;

	for (i = 0; i < (1 << trunk->hwidth); i++) {
		printf("%d: ", i);
		LIST_FOREACH(ifv, &trunk->hash[i], ifv_list)
			printf("%s ", ifv->ifv_ifp->if_xname);
		printf("\n");
	}
}
#endif /* 0 */
#endif /* !VLAN_ARRAY */

static void
trunk_destroy(struct ifvlantrunk *trunk)
{
	VLAN_LOCK_ASSERT();

	TRUNK_LOCK(trunk);
#ifndef VLAN_ARRAY
	vlan_freehash(trunk);
#endif
	trunk->parent->if_vlantrunk = NULL;
	LIST_REMOVE(trunk, trunk_entry);
	TRUNK_UNLOCK(trunk);
	TRUNK_LOCK_DESTROY(trunk);
	free(trunk, M_VLAN);
}

/*
 * Program our multicast filter. What we're actually doing is
 * programming the multicast filter of the parent. This has the
 * side effect of causing the parent interface to receive multicast
 * traffic that it doesn't really want, which ends up being discarded
 * later by the upper protocol layers. Unfortunately, there's no way
 * to avoid this: there really is only one physical interface.
 *
 * XXX: There is a possible race here if more than one thread is
 *      modifying the multicast state of the vlan interface at the same time.
 */
static int
vlan_setmulti(struct ifnet *ifp)
{
	struct ifnet		*ifp_p;
	struct ifmultiaddr	*ifma, *rifma = NULL;
	struct ifvlan		*sc;
	struct vlan_mc_entry	*mc = NULL;
	struct sockaddr_dl	sdl;
	int			error;

	/*VLAN_LOCK_ASSERT();*/

	/* Find the parent. */
	sc = ifp->if_softc;
	ifp_p = PARENT(sc);

	bzero((char *)&sdl, sizeof(sdl));
	sdl.sdl_len = sizeof(sdl);
	sdl.sdl_family = AF_LINK;
	sdl.sdl_index = ifp_p->if_index;
	sdl.sdl_type = IFT_ETHER;
	sdl.sdl_alen = ETHER_ADDR_LEN;

	/* First, remove any existing filter entries. */
	while (SLIST_FIRST(&sc->vlan_mc_listhead) != NULL) {
		mc = SLIST_FIRST(&sc->vlan_mc_listhead);
		bcopy((char *)&mc->mc_addr, LLADDR(&sdl), ETHER_ADDR_LEN);
		error = if_delmulti(ifp_p, (struct sockaddr *)&sdl);
		if (error)
			return (error);
		SLIST_REMOVE_HEAD(&sc->vlan_mc_listhead, mc_entries);
		free(mc, M_VLAN);
	}

	/* Now program new ones. */
	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != AF_LINK)
			continue;
		mc = malloc(sizeof(struct vlan_mc_entry), M_VLAN, M_NOWAIT);
		if (mc == NULL)
			return (ENOMEM);
		bcopy(LLADDR((struct sockaddr_dl *)ifma->ifma_addr),
		    (char *)&mc->mc_addr, ETHER_ADDR_LEN);
		SLIST_INSERT_HEAD(&sc->vlan_mc_listhead, mc, mc_entries);
		bcopy(LLADDR((struct sockaddr_dl *)ifma->ifma_addr),
		    LLADDR(&sdl), ETHER_ADDR_LEN);
		error = if_addmulti(ifp_p, (struct sockaddr *)&sdl, &rifma);
		if (error)
			return (error);
	}

	return (0);
}

/*
 * VLAN support can be loaded as a module.  The only place in the
 * system that's intimately aware of this is ether_input.  We hook
 * into this code through vlan_input_p which is defined there and
 * set here.  Noone else in the system should be aware of this so
 * we use an explicit reference here.
 */
extern	void (*vlan_input_p)(struct ifnet *, struct mbuf *);

/* For if_link_state_change() eyes only... */
extern	void (*vlan_link_state_p)(struct ifnet *, int);

static int
vlan_modevent(module_t mod, int type, void *data)
{

	switch (type) {
	case MOD_LOAD:
		LIST_INIT(&trunk_list);
		VLAN_LOCK_INIT();
		vlan_input_p = vlan_input;
		vlan_link_state_p = vlan_link_state;
		vlan_trunk_cap_p = vlan_trunk_capabilities;
		if_clone_attach(&vlan_cloner);
		break;
	case MOD_UNLOAD:
	    {
		struct ifvlantrunk *trunk, *trunk1;

		if_clone_detach(&vlan_cloner);
		vlan_input_p = NULL;
		vlan_link_state_p = NULL;
		vlan_trunk_cap_p = NULL;
		VLAN_LOCK();
		LIST_FOREACH_SAFE(trunk, &trunk_list, trunk_entry, trunk1)
			trunk_destroy(trunk);
		VLAN_UNLOCK();
		VLAN_LOCK_DESTROY();
		break;
	    }
	default:
		return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t vlan_mod = {
	"if_vlan",
	vlan_modevent,
	0
};

DECLARE_MODULE(if_vlan, vlan_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(if_vlan, 3);
MODULE_DEPEND(if_vlan, miibus, 1, 1, 1);

static struct ifnet *
vlan_clone_match_ethertag(struct if_clone *ifc, const char *name, int *tag)
{
	const char *cp;
	struct ifnet *ifp;
	int t = 0;

	/* Check for <etherif>.<vlan> style interface names. */
	IFNET_RLOCK();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (ifp->if_type != IFT_ETHER)
			continue;
		if (strncmp(ifp->if_xname, name, strlen(ifp->if_xname)) != 0)
			continue;
		cp = name + strlen(ifp->if_xname);
		if (*cp != '.')
			continue;
		for(; *cp != '\0'; cp++) {
			if (*cp < '0' || *cp > '9')
				continue;
			t = (t * 10) + (*cp - '0');
		}
		if (tag != NULL)
			*tag = t;
		break;
	}
	IFNET_RUNLOCK();

	return (ifp);
}

static int
vlan_clone_match(struct if_clone *ifc, const char *name)
{
	const char *cp;

	if (vlan_clone_match_ethertag(ifc, name, NULL) != NULL)
		return (1);

	if (strncmp(VLANNAME, name, strlen(VLANNAME)) != 0)
		return (0);
	for (cp = name + 4; *cp != '\0'; cp++) {
		if (*cp < '0' || *cp > '9')
			return (0);
	}

	return (1);
}

static int
vlan_clone_create(struct if_clone *ifc, char *name, size_t len)
{
	char *dp;
	int wildcard;
	int unit;
	int error;
	int tag;
	int ethertag;
	struct ifvlan *ifv;
	struct ifnet *ifp;
	struct ifnet *p;
	u_char eaddr[6] = {0,0,0,0,0,0};

	if ((p = vlan_clone_match_ethertag(ifc, name, &tag)) != NULL) {
		ethertag = 1;
		unit = -1;
		wildcard = 0;

		/*
		 * Don't let the caller set up a VLAN tag with
		 * anything except VLID bits.
		 */
		if (tag & ~EVL_VLID_MASK)
			return (EINVAL);
	} else {
		ethertag = 0;

		error = ifc_name2unit(name, &unit);
		if (error != 0)
			return (error);

		wildcard = (unit < 0);
	}

	error = ifc_alloc_unit(ifc, &unit);
	if (error != 0)
		return (error);

	/* In the wildcard case, we need to update the name. */
	if (wildcard) {
		for (dp = name; *dp != '\0'; dp++);
		if (snprintf(dp, len - (dp-name), "%d", unit) >
		    len - (dp-name) - 1) {
			panic("%s: interface name too long", __func__);
		}
	}

	ifv = malloc(sizeof(struct ifvlan), M_VLAN, M_WAITOK | M_ZERO);
	ifp = ifv->ifv_ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		ifc_free_unit(ifc, unit);
		free(ifv, M_VLAN);
		return (ENOSPC);
	}
	SLIST_INIT(&ifv->vlan_mc_listhead);

	ifp->if_softc = ifv;
	/*
	 * Set the name manually rather than using if_initname because
	 * we don't conform to the default naming convention for interfaces.
	 */
	strlcpy(ifp->if_xname, name, IFNAMSIZ);
	ifp->if_dname = ifc->ifc_name;
	ifp->if_dunit = unit;
	/* NB: flags are not set here */
	ifp->if_linkmib = &ifv->ifv_mib;
	ifp->if_linkmiblen = sizeof(ifv->ifv_mib);
	/* NB: mtu is not set here */

	ifp->if_init = vlan_ifinit;
	ifp->if_start = vlan_start;
	ifp->if_ioctl = vlan_ioctl;
	ifp->if_snd.ifq_maxlen = ifqmaxlen;
	ifp->if_flags = VLAN_IFFLAGS;
	ether_ifattach(ifp, eaddr);
	/* Now undo some of the damage... */
	ifp->if_baudrate = 0;
	ifp->if_type = IFT_L2VLAN;
	ifp->if_hdrlen = ETHER_VLAN_ENCAP_LEN;

	if (ethertag) {
		error = vlan_config(ifv, p, tag);
		if (error != 0) {
			/*
			 * Since we've partialy failed, we need to back
			 * out all the way, otherwise userland could get
			 * confused.  Thus, we destroy the interface.
			 */
			vlan_unconfig(ifp);
			ether_ifdetach(ifp);
			if_free_type(ifp, IFT_ETHER);
			free(ifv, M_VLAN);

			return (error);
		}
		ifp->if_drv_flags |= IFF_DRV_RUNNING;

		/* Update flags on the parent, if necessary. */
		vlan_setflags(ifp, 1);
	}

	return (0);
}

static int
vlan_clone_destroy(struct if_clone *ifc, struct ifnet *ifp)
{
	int unit;
	struct ifvlan *ifv = ifp->if_softc;

	unit = ifp->if_dunit;

	vlan_unconfig(ifp);

	ether_ifdetach(ifp);
	if_free_type(ifp, IFT_ETHER);

	free(ifv, M_VLAN);

	ifc_free_unit(ifc, unit);

	return (0);
}

/*
 * The ifp->if_init entry point for vlan(4) is a no-op.
 */
static void
vlan_ifinit(void *foo)
{

}

/*
 * The if_start method for vlan(4) interface. It doesn't
 * raises the IFF_DRV_OACTIVE flag, since it is called
 * only from IFQ_HANDOFF() macro in ether_output_frame().
 * If the interface queue is full, and vlan_start() is
 * not called, the queue would never get emptied and
 * interface would stall forever.
 */
static void
vlan_start(struct ifnet *ifp)
{
	struct ifvlan *ifv;
	struct ifnet *p;
	struct mbuf *m;
	int error;

	ifv = ifp->if_softc;
	p = PARENT(ifv);

	for (;;) {
		IF_DEQUEUE(&ifp->if_snd, m);
		if (m == 0)
			break;
		BPF_MTAP(ifp, m);

		/*
		 * Do not run parent's if_start() if the parent is not up,
		 * or parent's driver will cause a system crash.
		 */
		if (!((p->if_flags & IFF_UP) &&
		    (p->if_drv_flags & IFF_DRV_RUNNING))) {
			m_freem(m);
			ifp->if_collisions++;
			continue;
		}

		/*
		 * If underlying interface can do VLAN tag insertion itself,
		 * just pass the packet along. However, we need some way to
		 * tell the interface where the packet came from so that it
		 * knows how to find the VLAN tag to use, so we attach a
		 * packet tag that holds it.
		 */
		if (p->if_capenable & IFCAP_VLAN_HWTAGGING) {
			struct m_tag *mtag = (struct m_tag *)
			    uma_zalloc(zone_mtag_vlan, M_NOWAIT);
			if (mtag == NULL) {
				ifp->if_oerrors++;
				m_freem(m);
				continue;
			}
			VLAN_TAG_VALUE(mtag) = ifv->ifv_tag;
			m_tag_prepend(m, mtag);
			m->m_flags |= M_VLANTAG;
		} else {
			struct ether_vlan_header *evl;

			M_PREPEND(m, ifv->ifv_encaplen, M_DONTWAIT);
			if (m == NULL) {
				if_printf(ifp,
				    "unable to prepend VLAN header\n");
				ifp->if_oerrors++;
				continue;
			}
			/* M_PREPEND takes care of m_len, m_pkthdr.len for us */

			if (m->m_len < sizeof(*evl)) {
				m = m_pullup(m, sizeof(*evl));
				if (m == NULL) {
					if_printf(ifp,
					    "cannot pullup VLAN header\n");
					ifp->if_oerrors++;
					continue;
				}
			}

			/*
			 * Transform the Ethernet header into an Ethernet header
			 * with 802.1Q encapsulation.
			 */
			bcopy(mtod(m, char *) + ifv->ifv_encaplen,
			      mtod(m, char *), ETHER_HDR_LEN);
			evl = mtod(m, struct ether_vlan_header *);
			evl->evl_proto = evl->evl_encap_proto;
			evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
			evl->evl_tag = htons(ifv->ifv_tag);
#ifdef DEBUG
			printf("%s: %*D\n", __func__, (int)sizeof(*evl),
			    (unsigned char *)evl, ":");
#endif
		}

		/*
		 * Send it, precisely as ether_output() would have.
		 * We are already running at splimp.
		 */
		IFQ_HANDOFF(p, m, error);
		if (!error)
			ifp->if_opackets++;
		else
			ifp->if_oerrors++;
	}
}

static void
vlan_input(struct ifnet *ifp, struct mbuf *m)
{
	struct ifvlantrunk *trunk = ifp->if_vlantrunk;
	struct ifvlan *ifv;
	struct m_tag *mtag;
	uint16_t tag;

	KASSERT(trunk != NULL, ("%s: no trunk", __func__));

	if (m->m_flags & M_VLANTAG) {
		/*
		 * Packet is tagged, but m contains a normal
		 * Ethernet frame; the tag is stored out-of-band.
		 */
		mtag = m_tag_locate(m, MTAG_VLAN, MTAG_VLAN_TAG, NULL);
		KASSERT(mtag != NULL,
			("%s: M_VLANTAG without m_tag", __func__));
		tag = EVL_VLANOFTAG(VLAN_TAG_VALUE(mtag));
		m_tag_delete(m, mtag);
		m->m_flags &= ~M_VLANTAG;
	} else {
		struct ether_vlan_header *evl;

		/*
		 * Packet is tagged in-band as specified by 802.1q.
		 */
		mtag = NULL;
		switch (ifp->if_type) {
		case IFT_ETHER:
			if (m->m_len < sizeof(*evl) &&
			    (m = m_pullup(m, sizeof(*evl))) == NULL) {
				if_printf(ifp, "cannot pullup VLAN header\n");
				return;
			}
			evl = mtod(m, struct ether_vlan_header *);
			KASSERT(ntohs(evl->evl_encap_proto) == ETHERTYPE_VLAN,
				("%s: bad encapsulation protocol (%u)",
				 __func__, ntohs(evl->evl_encap_proto)));

			tag = EVL_VLANOFTAG(ntohs(evl->evl_tag));

			/*
			 * Restore the original ethertype.  We'll remove
			 * the encapsulation after we've found the vlan
			 * interface corresponding to the tag.
			 */
			evl->evl_encap_proto = evl->evl_proto;
			break;
		default:
			tag = (uint16_t) -1;
#ifdef INVARIANTS
			panic("%s: unsupported if_type (%u)",
			      __func__, ifp->if_type);
#endif
			break;
		}
	}

	/*
	 * In VLAN_ARRAY case we proceed completely lockless.
	 */
#ifdef VLAN_ARRAY
	ifv = trunk->vlans[tag];
	if (ifv == NULL || (ifv->ifv_ifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		ifp->if_noproto++;
		return;
	}
#else
	TRUNK_RLOCK(trunk);
	ifv = vlan_gethash(trunk, tag);
	if (ifv == NULL || (ifv->ifv_ifp->if_flags & IFF_UP) == 0) {
		TRUNK_RUNLOCK(trunk);
		m_freem(m);
		ifp->if_noproto++;
		return;
	}
	TRUNK_RUNLOCK(trunk);
#endif

	if (mtag == NULL) {
		/*
		 * Packet had an in-line encapsulation header;
		 * remove it.  The original header has already
		 * been fixed up above.
		 */
		bcopy(mtod(m, caddr_t),
		      mtod(m, caddr_t) + ETHER_VLAN_ENCAP_LEN,
		      ETHER_HDR_LEN);
		m_adj(m, ETHER_VLAN_ENCAP_LEN);
	}

	m->m_pkthdr.rcvif = ifv->ifv_ifp;
	ifv->ifv_ifp->if_ipackets++;

	/* Pass it back through the parent's input routine. */
	(*ifp->if_input)(ifv->ifv_ifp, m);
}

static int
vlan_config(struct ifvlan *ifv, struct ifnet *p, uint16_t tag)
{
	struct ifvlantrunk *trunk;
	struct ifnet *ifp;
	int error = 0;

	/* VID numbers 0x0 and 0xFFF are reserved */
	if (tag == 0 || tag == 0xFFF)
		return (EINVAL);
	if (p->if_type != IFT_ETHER)
		return (EPROTONOSUPPORT);
	if ((p->if_flags & VLAN_IFFLAGS) != VLAN_IFFLAGS)
		return (EPROTONOSUPPORT);
	if (ifv->ifv_trunk)
		return (EBUSY);

	if (p->if_vlantrunk == NULL) {
		trunk = malloc(sizeof(struct ifvlantrunk),
		    M_VLAN, M_WAITOK | M_ZERO);
#ifndef VLAN_ARRAY
		vlan_inithash(trunk);
#endif
		VLAN_LOCK();
		if (p->if_vlantrunk != NULL) {
			/* A race that that is very unlikely to be hit. */
#ifndef VLAN_ARRAY
			vlan_freehash(trunk);
#endif
			free(trunk, M_VLAN);
			goto exists;
		}
		TRUNK_LOCK_INIT(trunk);
		LIST_INSERT_HEAD(&trunk_list, trunk, trunk_entry);
		TRUNK_LOCK(trunk);
		p->if_vlantrunk = trunk;
		trunk->parent = p;
	} else {
		VLAN_LOCK();
exists:
		trunk = p->if_vlantrunk;
		TRUNK_LOCK(trunk);
	}

	ifv->ifv_tag = tag;
#ifdef VLAN_ARRAY
	if (trunk->vlans[tag] != NULL)
		error = EEXIST;
#else
	error = vlan_inshash(trunk, ifv);
#endif
	if (error)
		goto done;

	ifv->ifv_encaplen = ETHER_VLAN_ENCAP_LEN;
	ifv->ifv_mintu = ETHERMIN;
	ifv->ifv_pflags = 0;

	/*
	 * If the parent supports the VLAN_MTU capability,
	 * i.e. can Tx/Rx larger than ETHER_MAX_LEN frames,
	 * use it.
	 */
	if (p->if_capenable & IFCAP_VLAN_MTU) {
		/*
		 * No need to fudge the MTU since the parent can
		 * handle extended frames.
		 */
		ifv->ifv_mtufudge = 0;
	} else {
		/*
		 * Fudge the MTU by the encapsulation size.  This
		 * makes us incompatible with strictly compliant
		 * 802.1Q implementations, but allows us to use
		 * the feature with other NetBSD implementations,
		 * which might still be useful.
		 */
		ifv->ifv_mtufudge = ifv->ifv_encaplen;
	}

	ifv->ifv_trunk = trunk;
	ifp = ifv->ifv_ifp;
	ifp->if_mtu = p->if_mtu - ifv->ifv_mtufudge;
	ifp->if_baudrate = p->if_baudrate;
	/*
	 * Copy only a selected subset of flags from the parent.
	 * Other flags are none of our business.
	 */
#define VLAN_COPY_FLAGS (IFF_SIMPLEX)
	ifp->if_flags &= ~VLAN_COPY_FLAGS;
	ifp->if_flags |= p->if_flags & VLAN_COPY_FLAGS;
#undef VLAN_COPY_FLAGS

	ifp->if_link_state = p->if_link_state;

	vlan_capabilities(ifv);

	/*
	 * Set up our ``Ethernet address'' to reflect the underlying
	 * physical interface's.
	 */
	bcopy(IF_LLADDR(p), IF_LLADDR(ifp), ETHER_ADDR_LEN);

	/*
	 * Configure multicast addresses that may already be
	 * joined on the vlan device.
	 */
	(void)vlan_setmulti(ifp); /* XXX: VLAN lock held */

#ifdef VLAN_ARRAY
	atomic_store_rel_ptr((uintptr_t *)&trunk->vlans[tag], (uintptr_t)ifv);
	trunk->refcnt++;
#endif
done:
	TRUNK_UNLOCK(trunk);
	VLAN_UNLOCK();

	return (error);
}

static int
vlan_unconfig(struct ifnet *ifp)
{
	struct ifvlantrunk *trunk;
	struct vlan_mc_entry *mc;
	struct ifvlan *ifv;
	int error;

	VLAN_LOCK();

	ifv = ifp->if_softc;
	trunk = ifv->ifv_trunk;

	if (trunk) {
		struct sockaddr_dl sdl;
		struct ifnet *p = trunk->parent;

		TRUNK_LOCK(trunk);
#ifdef VLAN_ARRAY
		atomic_store_rel_ptr((uintptr_t *)&trunk->vlans[ifv->ifv_tag],
		    (uintptr_t)NULL);
		trunk->refcnt--;
#endif

		/*
		 * Since the interface is being unconfigured, we need to
		 * empty the list of multicast groups that we may have joined
		 * while we were alive from the parent's list.
		 */
		bzero((char *)&sdl, sizeof(sdl));
		sdl.sdl_len = sizeof(sdl);
		sdl.sdl_family = AF_LINK;
		sdl.sdl_index = p->if_index;
		sdl.sdl_type = IFT_ETHER;
		sdl.sdl_alen = ETHER_ADDR_LEN;

		while(SLIST_FIRST(&ifv->vlan_mc_listhead) != NULL) {
			mc = SLIST_FIRST(&ifv->vlan_mc_listhead);
			bcopy((char *)&mc->mc_addr, LLADDR(&sdl),
			    ETHER_ADDR_LEN);
			error = if_delmulti(p, (struct sockaddr *)&sdl);
			if (error)
				return (error);
			SLIST_REMOVE_HEAD(&ifv->vlan_mc_listhead, mc_entries);
			free(mc, M_VLAN);
		}

		vlan_setflags(ifp, 0); /* clear special flags on parent */
#ifndef VLAN_ARRAY
		vlan_remhash(trunk, ifv);
#endif
		ifv->ifv_trunk = NULL;

		/*
		 * Check if we were the last.
		 */
		if (trunk->refcnt == 0) {
			atomic_store_rel_ptr((uintptr_t *)
			    &trunk->parent->if_vlantrunk,
			    (uintptr_t)NULL);
			/*
			 * XXXGL: If some ithread has already entered
			 * vlan_input() and is now blocked on the trunk
			 * lock, then it should preempt us right after
			 * unlock and finish its work. Then we will acquire
			 * lock again in trunk_destroy().
			 * XXX: not true in case of VLAN_ARRAY
			 */
			TRUNK_UNLOCK(trunk);
			trunk_destroy(trunk);
		} else
			TRUNK_UNLOCK(trunk);
	}

	/* Disconnect from parent. */
	if (ifv->ifv_pflags)
		if_printf(ifp, "%s: ifv_pflags unclean\n", __func__);
	ifv->ifv_ifp->if_mtu = ETHERMTU;		/* XXX why not 0? */
	ifv->ifv_ifp->if_link_state = LINK_STATE_UNKNOWN;

	/* Clear our MAC address. */
	bzero(IF_LLADDR(ifv->ifv_ifp), ETHER_ADDR_LEN);

	VLAN_UNLOCK();

	return (0);
}

/* Handle a reference counted flag that should be set on the parent as well */
static int
vlan_setflag(struct ifnet *ifp, int flag, int status,
	     int (*func)(struct ifnet *, int))
{
	struct ifvlan *ifv;
	int error;

	/* XXX VLAN_LOCK_ASSERT(); */

	ifv = ifp->if_softc;
	status = status ? (ifp->if_flags & flag) : 0;
	/* Now "status" contains the flag value or 0 */

	/*
	 * See if recorded parent's status is different from what
	 * we want it to be.  If it is, flip it.  We record parent's
	 * status in ifv_pflags so that we won't clear parent's flag
	 * we haven't set.  In fact, we don't clear or set parent's
	 * flags directly, but get or release references to them.
	 * That's why we can be sure that recorded flags still are
	 * in accord with actual parent's flags.
	 */
	if (status != (ifv->ifv_pflags & flag)) {
		error = (*func)(PARENT(ifv), status);
		if (error)
			return (error);
		ifv->ifv_pflags &= ~flag;
		ifv->ifv_pflags |= status;
	}
	return (0);
}

/*
 * Handle IFF_* flags that require certain changes on the parent:
 * if "status" is true, update parent's flags respective to our if_flags;
 * if "status" is false, forcedly clear the flags set on parent.
 */
static int
vlan_setflags(struct ifnet *ifp, int status)
{
	int error, i;
	
	for (i = 0; vlan_pflags[i].flag; i++) {
		error = vlan_setflag(ifp, vlan_pflags[i].flag,
				     status, vlan_pflags[i].func);
		if (error)
			return (error);
	}
	return (0);
}

/* Inform all vlans that their parent has changed link state */
static void
vlan_link_state(struct ifnet *ifp, int link)
{
	struct ifvlantrunk *trunk = ifp->if_vlantrunk;
	struct ifvlan *ifv;
	int i;

	TRUNK_LOCK(trunk);
#ifdef VLAN_ARRAY
	for (i = 0; i < EVL_VLID_MASK+1; i++)
		if (trunk->vlans[i] != NULL) {
			ifv = trunk->vlans[i];
#else
	for (i = 0; i < (1 << trunk->hwidth); i++) {
		LIST_FOREACH(ifv, &trunk->hash[i], ifv_list)
#endif
			if_link_state_change(ifv->ifv_ifp,
			    trunk->parent->if_link_state);
	}
	TRUNK_UNLOCK(trunk);
}

static void
vlan_capabilities(struct ifvlan *ifv)
{
	struct ifnet *p = PARENT(ifv);
	struct ifnet *ifp = ifv->ifv_ifp;

	TRUNK_LOCK_ASSERT(TRUNK(ifv));

	/*
	 * If the parent interface can do checksum offloading
	 * on VLANs, then propagate its hardware-assisted
	 * checksumming flags. Also assert that checksum
	 * offloading requires hardware VLAN tagging.
	 */
	if (p->if_capabilities & IFCAP_VLAN_HWCSUM)
		ifp->if_capabilities = p->if_capabilities & IFCAP_HWCSUM;

	if (p->if_capenable & IFCAP_VLAN_HWCSUM &&
	    p->if_capenable & IFCAP_VLAN_HWTAGGING) {
		ifp->if_capenable = p->if_capenable & IFCAP_HWCSUM;
		ifp->if_hwassist = p->if_hwassist;
	} else {
		ifp->if_capenable = 0;
		ifp->if_hwassist = 0;
	}
}

static void
vlan_trunk_capabilities(struct ifnet *ifp)
{
	struct ifvlantrunk *trunk = ifp->if_vlantrunk;
	struct ifvlan *ifv;
	int i;

	TRUNK_LOCK(trunk);
#ifdef VLAN_ARRAY
	for (i = 0; i < EVL_VLID_MASK+1; i++)
		if (trunk->vlans[i] != NULL) {
			ifv = trunk->vlans[i];
#else
	for (i = 0; i < (1 << trunk->hwidth); i++) {
		LIST_FOREACH(ifv, &trunk->hash[i], ifv_list)
#endif
			vlan_capabilities(ifv);
	}
	TRUNK_UNLOCK(trunk);
}

static int
vlan_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifaddr *ifa;
	struct ifnet *p;
	struct ifreq *ifr;
	struct ifvlan *ifv;
	struct vlanreq vlr;
	int error = 0;

	ifr = (struct ifreq *)data;
	ifa = (struct ifaddr *)data;
	ifv = ifp->if_softc;

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;

		switch (ifa->ifa_addr->sa_family) {
#ifdef INET
		case AF_INET:
			arp_ifinit(ifv->ifv_ifp, ifa);
			break;
#endif
		default:
			break;
		}
		break;

	case SIOCGIFADDR:
		{
			struct sockaddr *sa;

			sa = (struct sockaddr *) &ifr->ifr_data;
			bcopy(IF_LLADDR(ifp), (caddr_t)sa->sa_data,
			    ETHER_ADDR_LEN);
		}
		break;

	case SIOCGIFMEDIA:
		VLAN_LOCK();
		if (TRUNK(ifv) != NULL) {
			error = (*PARENT(ifv)->if_ioctl)(PARENT(ifv),
					SIOCGIFMEDIA, data);
			VLAN_UNLOCK();
			/* Limit the result to the parent's current config. */
			if (error == 0) {
				struct ifmediareq *ifmr;

				ifmr = (struct ifmediareq *)data;
				if (ifmr->ifm_count >= 1 && ifmr->ifm_ulist) {
					ifmr->ifm_count = 1;
					error = copyout(&ifmr->ifm_current,
						ifmr->ifm_ulist,
						sizeof(int));
				}
			}
		} else {
			VLAN_UNLOCK();
			error = EINVAL;
		}
		break;

	case SIOCSIFMEDIA:
		error = EINVAL;
		break;

	case SIOCSIFMTU:
		/*
		 * Set the interface MTU.
		 */
		VLAN_LOCK();
		if (TRUNK(ifv) != NULL) {
			if (ifr->ifr_mtu >
			     (PARENT(ifv)->if_mtu - ifv->ifv_mtufudge) ||
			    ifr->ifr_mtu <
			     (ifv->ifv_mintu - ifv->ifv_mtufudge))
				error = EINVAL;
			else
				ifp->if_mtu = ifr->ifr_mtu;
		} else
			error = EINVAL;
		VLAN_UNLOCK();
		break;

	case SIOCSETVLAN:
		error = copyin(ifr->ifr_data, &vlr, sizeof(vlr));
		if (error)
			break;
		if (vlr.vlr_parent[0] == '\0') {
			vlan_unconfig(ifp);
			ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
			break;
		}
		p = ifunit(vlr.vlr_parent);
		if (p == 0) {
			error = ENOENT;
			break;
		}
		/*
		 * Don't let the caller set up a VLAN tag with
		 * anything except VLID bits.
		 */
		if (vlr.vlr_tag & ~EVL_VLID_MASK) {
			error = EINVAL;
			break;
		}
		error = vlan_config(ifv, p, vlr.vlr_tag);
		if (error)
			break;
		ifp->if_drv_flags |= IFF_DRV_RUNNING;

		/* Update flags on the parent, if necessary. */
		vlan_setflags(ifp, 1);
		break;

	case SIOCGETVLAN:
		bzero(&vlr, sizeof(vlr));
		VLAN_LOCK();
		if (TRUNK(ifv) != NULL) {
			strlcpy(vlr.vlr_parent, PARENT(ifv)->if_xname,
			    sizeof(vlr.vlr_parent));
			vlr.vlr_tag = ifv->ifv_tag;
		}
		VLAN_UNLOCK();
		error = copyout(&vlr, ifr->ifr_data, sizeof(vlr));
		break;
		
	case SIOCSIFFLAGS:
		/*
		 * We should propagate selected flags to the parent,
		 * e.g., promiscuous mode.
		 */
		if (TRUNK(ifv) != NULL)
			error = vlan_setflags(ifp, 1);
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		/*
		 * If we don't have a parent, just remember the membership for
		 * when we do.
		 */
		if (TRUNK(ifv) != NULL)
			error = vlan_setmulti(ifp);
		break;

	default:
		error = EINVAL;
	}

	return (error);
}
