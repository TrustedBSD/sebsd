/*	$FreeBSD: src/contrib/ipfilter/lib/facpri.h,v 1.3 2005/12/30 11:52:23 guido Exp $	*/

/*
 * Copyright (C) 1999-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#ifndef	__FACPRI_H__
#define	__FACPRI_H__

#ifndef	__P
# define P_DEF
# ifdef	__STDC__
#  define	__P(x) x
# else
#  define	__P(x) ()
# endif
#endif

extern	char	*fac_toname __P((int));
extern	int	fac_findname __P((char *));

extern	char	*pri_toname __P((int));
extern	int	pri_findname __P((char *));

#ifdef P_DEF
# undef	__P
# undef	P_DEF
#endif

#if LOG_CRON == (9<<3)
# define	LOG_CRON1	LOG_CRON
# define	LOG_CRON2	(15<<3)
#endif
#if LOG_CRON == (15<<3)
# define	LOG_CRON1	(9<<3)
# define	LOG_CRON2	LOG_CRON
#endif

#endif /* __FACPRI_H__ */