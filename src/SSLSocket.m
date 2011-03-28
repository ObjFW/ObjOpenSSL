#include <unistd.h>
#include <errno.h>
#include <assert.h>

#import <ObjFW/OFHTTPRequest.h>

#import "SSLSocket.h"

#import <ObjFW/OFAcceptFailedException.h>
#import <ObjFW/OFConnectionFailedException.h>
#import <ObjFW/OFInitializationFailedException.h>
#import <ObjFW/OFNotConnectedException.h>
#import <ObjFW/OFOutOfRangeException.h>
#import <ObjFW/OFReadFailedException.h>
#import <ObjFW/OFWriteFailedException.h>

#ifndef INVALID_SOCKET
# define INVALID_SOCKET -1
#endif

@implementation SSLSocket
+ (void)load
{
	of_http_request_tls_socket_class = self;
}

+ (void)initialize
{
	if (self == [SSLSocket class])
		SSL_library_init();
}

- init
{
	self = [super init];

	@try {
		if ((ctx = SSL_CTX_new(SSLv23_method())) == NULL)
			@throw [OFInitializationFailedException
			    newWithClass: isa];

		if ((SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2) &
		    SSL_OP_NO_SSLv2) == 0)
			@throw [OFInitializationFailedException
			    newWithClass: isa];
	} @catch (id e) {
		[self release];
		@throw e;
	}

	return self;
}

- initWithSocket: (OFTCPSocket*)socket
{
	self = [self init];

	@try {
		sock = dup(socket->sock);

		if ((ssl = SSL_new(ctx)) == NULL || !SSL_set_fd(ssl, sock)) {
			close(sock);
			sock = INVALID_SOCKET;
			@throw [OFInitializationFailedException
			    newWithClass: isa];
		}

		SSL_set_connect_state(ssl);

		if (SSL_connect(ssl) != 1) {
			close(sock);
			sock = INVALID_SOCKET;
			@throw [OFInitializationFailedException
			    newWithClass: isa];
		}
	} @catch (id e) {
		[self release];
		@throw e;
	}

	return self;
}

- (void)dealloc
{
	SSL_CTX *ctx_ = ctx;
	SSL *ssl_ = ssl;

	[super dealloc];

	if (ssl_ != NULL)
		SSL_free(ssl_);
	if (ctx_ != NULL)
		SSL_CTX_free(ctx_);
}

- (void)connectToHost: (OFString*)host
	       onPort: (uint16_t)port
{
	[super connectToHost: host
		      onPort: port];

	if ((ssl = SSL_new(ctx)) == NULL || !SSL_set_fd(ssl, sock)) {
		[super close];
		@throw [OFConnectionFailedException newWithClass: isa
							  socket: self
							    host: host
							    port: port];
	}

	SSL_set_connect_state(ssl);

	if (SSL_connect(ssl) != 1) {
		[super close];
		@throw [OFConnectionFailedException newWithClass: isa
							  socket: self
							    host: host
							    port: port];
	}
}

- (SSLSocket*)accept
{
	SSLSocket *newsock = (SSLSocket*)[super accept];

	if ((ssl = SSL_new(ctx)) == NULL || !SSL_set_fd(ssl, sock)) {
		[super close];
		@throw [OFAcceptFailedException newWithClass: isa
						      socket: self];
	}

	SSL_set_accept_state(ssl);

	if (SSL_connect(ssl) != 1) {
		[super close];
		@throw [OFAcceptFailedException newWithClass: isa
						      socket: self];
	}

	return newsock;
}

- (void)close
{
	SSL_shutdown(ssl);

	[super close];
}

- (size_t)_readNBytes: (size_t)size
	   intoBuffer: (char*)buf
{
	ssize_t ret;

	if (size > INT_MAX)
		@throw [OFOutOfRangeException newWithClass: isa];

	if (sock == INVALID_SOCKET)
		@throw [OFNotConnectedException newWithClass: isa
						      socket: self];

	if (eos) {
		OFReadFailedException *e;

		e = [OFReadFailedException newWithClass: isa
						 stream: self
					  requestedSize: size];
#ifndef _WIN32
		e->errNo = ENOTCONN;
#else
		e->errNo = WSAENOTCONN;
#endif

		@throw e;
	}

	if ((ret = SSL_read(ssl, buf, (int)size)) < 0)
		@throw [OFReadFailedException newWithClass: isa
						    stream: self
					     requestedSize: size];

	if (ret == 0)
		eos = YES;

	return ret;
}

- (size_t)_writeNBytes: (size_t)size
	    fromBuffer: (const char*)buf
{
	ssize_t ret;

	if (size > INT_MAX)
		@throw [OFOutOfRangeException newWithClass: isa];

	if (sock == INVALID_SOCKET)
		@throw [OFNotConnectedException newWithClass: isa
						      socket: self];

	if (eos) {
		OFWriteFailedException *e;

		e = [OFWriteFailedException newWithClass: isa
						  stream: self
					   requestedSize: size];

#ifndef _WIN32
		e->errNo = ENOTCONN;
#else
		e->errNo = WSAENOTCONN;
#endif

		@throw e;
	}

	if ((ret = SSL_write(ssl, buf, (int)size)) < 1)
		@throw [OFWriteFailedException newWithClass: isa
						     stream: self
					      requestedSize: size];

	return ret;
}
@end
