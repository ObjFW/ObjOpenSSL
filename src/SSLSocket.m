/*
 * Copyright (c) 2011, Jonathan Schleifer <js@webkeks.org>
 * Copyright (c) 2011, Florian Zeitz <florob@babelmonkeys.de>
 * Copyright (c) 2011, Jos Kuijpers <jos@kuijpersvof.nl>
 *
 * https://webkeks.org/git/?p=objopenssl.git
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

#include <openssl/crypto.h>
#include <openssl/err.h>

#import <ObjFW/OFThread.h>
#import <ObjFW/OFHTTPRequest.h>
#import <ObjFW/OFDataArray.h>

#import <ObjFW/OFAcceptFailedException.h>
#import <ObjFW/OFConnectionFailedException.h>
#import <ObjFW/OFInitializationFailedException.h>
#import <ObjFW/OFInvalidArgumentException.h>
#import <ObjFW/OFNotConnectedException.h>
#import <ObjFW/OFOutOfRangeException.h>
#import <ObjFW/OFReadFailedException.h>
#import <ObjFW/OFWriteFailedException.h>
#import <ObjFW/macros.h>
#import <ObjFW/threading.h>

#import "SSLSocket.h"
#import "SSLInvalidCertificateException.h"
#import "X509Certificate.h"

#ifndef INVALID_SOCKET
# define INVALID_SOCKET -1
#endif

static SSL_CTX *ctx;
static of_mutex_t *ssl_mutexes;

static unsigned long
get_thread_id(void)
{
	return (unsigned long)(uintptr_t)[OFThread currentThread];
}

static void
locking_callback(int mode, int n, const char *file, int line)
{
	/*
	 * This function must handle up to CRYPTO_num_locks() mutexes.
	 * It must set the n-th lock if mode & CRYPTO_LOCK,
	 * release it otherwise.
	 */
	if (mode & CRYPTO_LOCK)
		of_mutex_lock(&ssl_mutexes[n]);
	else
		of_mutex_unlock(&ssl_mutexes[n]);
}

@implementation SSLSocket
+ (void)load
{
	of_tls_socket_class = self;
}

+ (void)initialize
{
	int m;

	if (self != [SSLSocket class])
		return;

	CRYPTO_set_id_callback(&get_thread_id);

	/* Generate number of mutexes needed */
	m = CRYPTO_num_locks();
	ssl_mutexes = malloc(m * sizeof(of_mutex_t));
	for (m--; m >= 0; m--)
		of_mutex_new(&ssl_mutexes[m]);

	CRYPTO_set_locking_callback(&locking_callback);

	SSL_library_init();

	if ((ctx = SSL_CTX_new(SSLv23_method())) == NULL)
		@throw [OFInitializationFailedException
		    exceptionWithClass: self];

	if ((SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2) & SSL_OP_NO_SSLv2) == 0)
		@throw [OFInitializationFailedException
		    exceptionWithClass: self];

	if (SSL_CTX_set_default_verify_paths(ctx) == 0)
		@throw [OFInitializationFailedException
		    exceptionWithClass: self];
}

- initWithSocket: (OFTCPSocket*)socket
{
	return [self initWithSocket: socket
		     privateKeyFile: nil
		    certificateFile: nil];
}

-  initWithSocket: (OFTCPSocket*)socket
   privateKeyFile: (OFString*)privateKeyFile_
  certificateFile: (OFString*)certificateFile_
{
	self = [self init];

	@try {
		/* FIXME: Also allow with accepted sockets */

		privateKeyFile = [privateKeyFile_ copy];
		certificateFile = [certificateFile_ copy];

		sock = dup(socket->sock);

		if ((ssl = SSL_new(ctx)) == NULL || !SSL_set_fd(ssl, sock)) {
			close(sock);
			sock = INVALID_SOCKET;
			@throw [OFInitializationFailedException
			    exceptionWithClass: [self class]];
		}

		SSL_set_connect_state(ssl);

		if ((privateKeyFile != nil && !SSL_use_PrivateKey_file(ssl,
		    [privateKeyFile cStringUsingEncoding:
		    OF_STRING_ENCODING_NATIVE], SSL_FILETYPE_PEM)) ||
		    (certificateFile != nil && !SSL_use_certificate_file(ssl,
		    [certificateFile cStringUsingEncoding:
		    OF_STRING_ENCODING_NATIVE], SSL_FILETYPE_PEM)) ||
		    SSL_connect(ssl) != 1) {
			close(sock);
			sock = INVALID_SOCKET;
			@throw [OFInitializationFailedException
			    exceptionWithClass: [self class]];
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
		@throw [OFConnectionFailedException
		    exceptionWithClass: [self class]
				socket: self
				  host: host
				  port: port];
	}

	SSL_set_connect_state(ssl);

	if ((privateKeyFile != nil && !SSL_use_PrivateKey_file(ssl,
	    [privateKeyFile cStringUsingEncoding: OF_STRING_ENCODING_NATIVE],
	    SSL_FILETYPE_PEM)) || (certificateFile != nil &&
	    !SSL_use_certificate_file(ssl, [certificateFile
	    cStringUsingEncoding: OF_STRING_ENCODING_NATIVE],
	    SSL_FILETYPE_PEM)) || SSL_connect(ssl) != 1) {
		[super close];
		@throw [OFConnectionFailedException
		    exceptionWithClass: [self class]
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
		object_setClass(newSocket, [OFTCPSocket class]);
		[newSocket close];
		object_setClass(newSocket, object_getClass(self));

		@throw [OFAcceptFailedException exceptionWithClass: [self class]
							    socket: self];
	}

	SSL_set_accept_state(newSocket->ssl);

	if (!SSL_use_PrivateKey_file(newSocket->ssl, [privateKeyFile
	    cStringUsingEncoding: OF_STRING_ENCODING_NATIVE],
	    SSL_FILETYPE_PEM) || !SSL_use_certificate_file(newSocket->ssl,
	    [certificateFile cStringUsingEncoding: OF_STRING_ENCODING_NATIVE],
	    SSL_FILETYPE_PEM) || SSL_accept(newSocket->ssl) != 1) {
		/* We only want to close the OFTCPSocket */
		object_setClass(newSocket, [OFTCPSocket class]);
		[newSocket close];
		object_setClass(newSocket, object_getClass(self));

		@throw [OFAcceptFailedException exceptionWithClass: [self class]
							    socket: self];
	}

	return newSocket;
}

- (void)close
{
	if (ssl != NULL)
		SSL_shutdown(ssl);

	[super close];
}

- (size_t)lowlevelReadIntoBuffer: (void*)buffer
			  length: (size_t)length
{
	ssize_t ret;

	if (length > INT_MAX)
		@throw [OFOutOfRangeException exceptionWithClass: [self class]];

	if (sock == INVALID_SOCKET)
		@throw [OFNotConnectedException exceptionWithClass: [self class]
							    socket: self];

	if (atEndOfStream) {
		OFReadFailedException *e;

		e = [OFReadFailedException exceptionWithClass: [self class]
						       stream: self
					      requestedLength: length];
#ifndef _WIN32
		e->errNo = ENOTCONN;
#else
		e->errNo = WSAENOTCONN;
#endif

		@throw e;
	}

	if ((ret = SSL_read(ssl, buffer, (int)length)) < 0) {
		if (SSL_get_error(ssl, ret) ==  SSL_ERROR_WANT_READ)
			return 0;

		@throw [OFReadFailedException exceptionWithClass: [self class]
							  stream: self
						 requestedLength: length];
	}

	if (ret == 0)
		atEndOfStream = YES;

	return ret;
}

- (void)lowlevelWriteBuffer: (const void*)buffer
		     length: (size_t)length
{
	if (length > INT_MAX)
		@throw [OFOutOfRangeException exceptionWithClass: [self class]];

	if (sock == INVALID_SOCKET)
		@throw [OFNotConnectedException exceptionWithClass: [self class]
							    socket: self];

	if (atEndOfStream) {
		OFWriteFailedException *e;

		e = [OFWriteFailedException exceptionWithClass: [self class]
							stream: self
					       requestedLength: length];

#ifndef _WIN32
		e->errNo = ENOTCONN;
#else
		e->errNo = WSAENOTCONN;
#endif

		@throw e;
	}

	if (SSL_write(ssl, buffer, (int)length) < length)
		@throw [OFWriteFailedException exceptionWithClass: [self class]
							   stream: self
						  requestedLength: length];
}

- (size_t)pendingBytes
{
	if (ssl == NULL)
		return [super pendingBytes];

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

- (OFDataArray*)channelBindingDataWithType: (OFString*)type
{
	size_t length;
	char buffer[64];
	OFDataArray *data;

	if (![type isEqual: @"tls-unique"])
		@throw [OFInvalidArgumentException
		    exceptionWithClass: [self class]
			      selector: _cmd];

	if (SSL_session_reused(ssl) ^ !listening) {
		/*
		 * We are either client or the session has been resumed
		 * => we have sent the finished message
		 */
		length = SSL_get_finished(ssl, buffer, 64);
	} else {
		/* peer sent the finished message */
		length = SSL_get_peer_finished(ssl, buffer, 64);
	}

	data = [OFDataArray dataArray];
	[data addItems: buffer
		 count: length];

	return data;
}

- (X509Certificate*)peerCertificate
{
	X509 *certificate = SSL_get_peer_certificate(ssl);

	if (!certificate)
		return nil;

	return [[[X509Certificate alloc]
	    initWithX509Struct: certificate] autorelease];
}

- (void)verifyPeerCertificate
{
	unsigned long ret;

	if (SSL_get_peer_certificate(ssl) != NULL) {
		if ((ret = SSL_get_verify_result(ssl)) != X509_V_OK) {
			const char *tmp = X509_verify_cert_error_string(ret);
			OFString *reason = [OFString stringWithUTF8String: tmp];
			@throw [SSLInvalidCertificateException
			    exceptionWithClass: [self class]
					reason: reason];
		}
	} else
		@throw [SSLInvalidCertificateException
		    exceptionWithClass: [self class]
				reason: @"No certificate"];
}
@end
