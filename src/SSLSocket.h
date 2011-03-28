#include <openssl/ssl.h>

#import <ObjFW/OFTCPSocket.h>

@interface SSLSocket: OFTCPSocket
{
	SSL *ssl;
	OFString *privateKeyFile;
	OFString *certificateFile;
}

#ifdef OF_HAVE_PROPERTIES
@property (copy) OFString *privateKeyFile;
@property (copy) OFString *certificateFile;
#endif

- initWithSocket: (OFTCPSocket*)socket;
/* Change the return type */
- (SSLSocket*)accept;
- (void)setPrivateKeyFile: (OFString*)file;
- (OFString*)privateKeyFile;
- (void)setCertificateFile: (OFString*)file;
- (OFString*)certificateFile;
@end
