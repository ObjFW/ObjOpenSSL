include ../extra.mk

SHARED_LIB = ${OBJOPENSSL_SHARED_LIB}
STATIC_LIB = ${OBJOPENSSL_STATIC_LIB}
LIB_MAJOR = 0
LIB_MINOR = 0

SRCS = SSLConnectionFailedException.m	\
       SSLInvalidCertificateException.m	\
       SSLSocket.m			\
       X509Certificate.m

INCLUDES = ${SRCS:.m=.h}	\
	   ObjOpenSSL.h

include ../buildsys.mk

LD = ${OBJC}
