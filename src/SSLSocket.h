#include <openssl/ssl.h>

#import <ObjFW/OFTCPSocket.h>

@interface SSLSocket: OFTCPSocket
{
	SSL *ssl;
}

- initWithSocket: (OFTCPSocket*)socket;

/* Change the return type */
- (SSLSocket*)accept;
@end
