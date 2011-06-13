/*
 * Copyright (c) 2011, Jonathan Schleifer <js@webkeks.org>
 *
 * https://webkeks.org/hg/objxmpp/
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice is present in all copies.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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
#import <ObjFW/macros.h>

#ifndef INVALID_SOCKET
# define INVALID_SOCKET -1
#endif

static SSL_CTX *ctx;

@implementation SSLSocket
+ (void)load
{
	of_http_request_tls_socket_class = self;
}

+ (void)initialize
{
	if (self != [SSLSocket class])
		return;

	SSL_library_init();

	if ((ctx = SSL_CTX_new(SSLv23_method())) == NULL)
		@throw [OFInitializationFailedException newWithClass: self];

	if ((SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2) & SSL_OP_NO_SSLv2) == 0)
		@throw [OFInitializationFailedException newWithClass: self];
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

		if ((privateKeyFile != nil && !SSL_use_PrivateKey_file(ssl,
		    [privateKeyFile cString], SSL_FILETYPE_PEM)) ||
		    (certificateFile != nil && !SSL_use_certificate_file(ssl,
		    [certificateFile cString], SSL_FILETYPE_PEM)) ||
		    SSL_connect(ssl) != 1) {
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
	SSL *ssl_ = ssl;

	[privateKeyFile release];
	[certificateFile release];

	[super dealloc];

	if (ssl_ != NULL)
		SSL_free(ssl_);
}

- (void)connectToHost: (OFString*)host
		 port: (uint16_t)port
{
	[super connectToHost: host
			port: port];

	if ((ssl = SSL_new(ctx)) == NULL || !SSL_set_fd(ssl, sock)) {
		[super close];
		@throw [OFConnectionFailedException newWithClass: isa
							  socket: self
							    host: host
							    port: port];
	}

	SSL_set_connect_state(ssl);

	if ((privateKeyFile != nil && !SSL_use_PrivateKey_file(ssl,
	    [privateKeyFile cString], SSL_FILETYPE_PEM)) ||
	    (certificateFile != nil && !SSL_use_certificate_file(ssl,
	    [certificateFile cString], SSL_FILETYPE_PEM)) ||
	    SSL_connect(ssl) != 1) {
		[super close];
		@throw [OFConnectionFailedException newWithClass: isa
							  socket: self
							    host: host
							    port: port];
	}
}

- (SSLSocket*)accept
{
	SSLSocket *newSocket = (SSLSocket*)[super accept];

	if ((newSocket->ssl = SSL_new(ctx)) == NULL ||
	    !SSL_set_fd(newSocket->ssl, newSocket->sock)) {
		/* We only want to close the OFTCPSocket */
		newSocket->isa = [OFTCPSocket class];
		[newSocket close];
		newSocket->isa = isa;

		@throw [OFAcceptFailedException newWithClass: isa
						      socket: self];
	}

	SSL_set_accept_state(newSocket->ssl);

	if (!SSL_use_PrivateKey_file(newSocket->ssl, [privateKeyFile cString],
	    SSL_FILETYPE_PEM) || !SSL_use_certificate_file(newSocket->ssl,
	    [certificateFile cString], SSL_FILETYPE_PEM) ||
	    SSL_accept(newSocket->ssl) != 1) {
		/* We only want to close the OFTCPSocket */
		newSocket->isa = [OFTCPSocket class];
		[newSocket close];
		newSocket->isa = isa;

		@throw [OFAcceptFailedException newWithClass: isa
						      socket: self];
	}

	return newSocket;
}

- (void)close
{
	SSL_shutdown(ssl);

	[super close];
}

- (size_t)_readNBytes: (size_t)length
	   intoBuffer: (char*)buffer
{
	ssize_t ret;

	if (length > INT_MAX)
		@throw [OFOutOfRangeException newWithClass: isa];

	if (sock == INVALID_SOCKET)
		@throw [OFNotConnectedException newWithClass: isa
						      socket: self];

	if (isAtEndOfStream) {
		OFReadFailedException *e;

		e = [OFReadFailedException newWithClass: isa
						 stream: self
					requestedLength: length];
#ifndef _WIN32
		e->errNo = ENOTCONN;
#else
		e->errNo = WSAENOTCONN;
#endif

		@throw e;
	}

	if ((ret = SSL_read(ssl, buffer, (int)length)) < 0)
		@throw [OFReadFailedException newWithClass: isa
						    stream: self
					   requestedLength: length];

	if (ret == 0)
		isAtEndOfStream = YES;

	return ret;
}

- (size_t)_writeNBytes: (size_t)length
	    fromBuffer: (const char*)buffer
{
	ssize_t ret;

	if (length > INT_MAX)
		@throw [OFOutOfRangeException newWithClass: isa];

	if (sock == INVALID_SOCKET)
		@throw [OFNotConnectedException newWithClass: isa
						      socket: self];

	if (isAtEndOfStream) {
		OFWriteFailedException *e;

		e = [OFWriteFailedException newWithClass: isa
						  stream: self
					 requestedLength: length];

#ifndef _WIN32
		e->errNo = ENOTCONN;
#else
		e->errNo = WSAENOTCONN;
#endif

		@throw e;
	}

	if ((ret = SSL_write(ssl, buffer, (int)length)) < 1)
		@throw [OFWriteFailedException newWithClass: isa
						     stream: self
					    requestedLength: length];

	return ret;
}

- (size_t)pendingBytes
{
	return [super pendingBytes] + SSL_pending(ssl);
}

- (void)setPrivateKeyFile: (OFString*)file
{
	OF_SETTER(privateKeyFile, file, YES, YES)
}

- (OFString*)privateKeyFile
{
	OF_GETTER(privateKeyFile, YES)
}

- (void)setCertificateFile: (OFString*)file
{
	OF_SETTER(certificateFile, file, YES, YES)
}

- (OFString*)certificateFile
{
	OF_GETTER(certificateFile, YES)
}
@end
