# $FreeBSD: src/sys/modules/crypto/Makefile,v 1.4 2006/02/27 16:56:21 wkoszek Exp $

.PATH:	${.CURDIR}/../../opencrypto
.PATH:	${.CURDIR}/../../crypto
.PATH:	${.CURDIR}/../../crypto/blowfish
.PATH:	${.CURDIR}/../../crypto/des
.PATH:	${.CURDIR}/../../crypto/rijndael
.PATH:	${.CURDIR}/../../crypto/sha2

KMOD	= crypto
SRCS	= crypto.c
SRCS	+= criov.c cryptosoft.c xform.c
SRCS	+= cast.c deflate.c rmd160.c rijndael-alg-fst.c rijndael-api.c
SRCS	+= skipjack.c bf_enc.c bf_skey.c
SRCS	+= des_ecb.c des_enc.c des_setkey.c
SRCS	+= sha1.c sha2.c
SRCS	+= opt_param.h

.include <bsd.kmod.mk>
