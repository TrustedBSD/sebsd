.PATH: ${.CURDIR}/../../crypto
.PATH: ${.CURDIR}/../../security/mac_chkexec
CFLAGS+=	-g
# 
# Un comment the following line to enable debugging
KMOD=	mac_chkexec
SRCS=	vnode_if.h \
	sha1.c \
	mac_chkexec.c

.include <bsd.kmod.mk>
