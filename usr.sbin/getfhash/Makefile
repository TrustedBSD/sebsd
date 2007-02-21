PROG=	getfhash
LINKS=  ${BINDIR}/getfhash ${BINDIR}/setfhash
WARNS=	6
DPADD=	${LIBMD}
LDADD=	-lmd
MAN=	getfhash.8 setfhash.8

CFLAGS+=-I${.CURDIR}/../../sys/

.include <bsd.prog.mk>
