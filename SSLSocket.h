#include <openssl/ssl.h>

#import <ObjFW/OFTCPSocket.h>

@interface SSLSocket: OFTCPSocket
{
	SSL_CTX *ctx;
	SSL *ssl;
	BOOL handsShaken;
}

/* Change the return type */
- (SSLSocket*)accept;
@end
