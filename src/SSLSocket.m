/*
 * Copyright (c) 2011, 2012, 2013, 2014, 2015, 2016
 *     Jonathan Schleifer <js@heap.zone>
 * Copyright (c) 2011, Florian Zeitz <florob@babelmonkeys.de>
 * Copyright (c) 2011, Jos Kuijpers <jos@kuijpersvof.nl>
 *
 * https://heap.zone/git/objopenssl.git
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

#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wdocumentation"
#endif

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if defined(__clang__)
# pragma clang diagnostic pop
#endif

#import <ObjFW/OFThread.h>
#import <ObjFW/OFHTTPRequest.h>
#import <ObjFW/OFDataArray.h>
#import <ObjFW/OFLocalization.h>

#import <ObjFW/OFAcceptFailedException.h>
#import <ObjFW/OFInitializationFailedException.h>
#import <ObjFW/OFInvalidArgumentException.h>
#import <ObjFW/OFNotOpenException.h>
#import <ObjFW/OFOutOfRangeException.h>
#import <ObjFW/OFReadFailedException.h>
#import <ObjFW/OFWriteFailedException.h>

#import <ObjFW/macros.h>
#import <ObjFW/threading.h>

#import "SSLSocket.h"
#import "X509Certificate.h"

#import "SSLConnectionFailedException.h"
#import "SSLInvalidCertificateException.h"

#ifndef INVALID_SOCKET
# define INVALID_SOCKET -1
#endif

static SSL_CTX *ctx;
static of_mutex_t *ssl_mutexes;

#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wunused-function"
#endif
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
#if defined(__clang__)
# pragma clang diagnostic pop
#endif

@implementation SSLSocket
@synthesize delegate = _delegate, certificateFile = _certificateFile;
@synthesize privateKeyFile = _privateKeyFile;
@synthesize privateKeyPassphrase = privateKeyPassphrase;
@synthesize certificateVerificationEnabled = _certificateVerificationEnabled;
@synthesize requestClientCertificatesEnabled =
    _requestClientCertificatesEnabled;

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

	if ((SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2) & SSL_OP_NO_SSLv2) != SSL_OP_NO_SSLv2)
		@throw [OFInitializationFailedException
		    exceptionWithClass: self];

	if (SSL_CTX_set_default_verify_paths(ctx) == 0)
		@throw [OFInitializationFailedException
		    exceptionWithClass: self];
}

- init
{
	self = [super init];

	_certificateVerificationEnabled = true;

	return self;
}

- initWithSocket: (OFTCPSocket*)socket
{
	self = [self init];

	@try {
		if ((_socket = dup(socket->_socket)) < 0)
			@throw [OFInitializationFailedException exception];
	} @catch (id e) {
		[self release];
		@throw e;
	}

	return self;
}

- (void)dealloc
{
	SSL *SSL_ = _SSL;

	[_privateKeyFile release];
	[_certificateFile release];

	[super dealloc];

	if (SSL_ != NULL)
		SSL_free(SSL_);
}

- (void)SSL_startTLSWithExpectedHost: (OFString*)host
				port: (uint16_t)port
{
	of_string_encoding_t encoding;

	if ((_SSL = SSL_new(ctx)) == NULL || SSL_set_fd(_SSL, _socket) != 1) {
		unsigned long error = ERR_get_error();

		[super close];

		@throw [SSLConnectionFailedException
		    exceptionWithHost: host
				 port: port
			       socket: self
			     SSLError: error];
	}

	if (_certificateVerificationEnabled) {
		X509_VERIFY_PARAM *param = SSL_get0_param(_SSL);

		X509_VERIFY_PARAM_set_hostflags(param,
		    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

		if (X509_VERIFY_PARAM_set1_host(param,
		    [host UTF8String], [host UTF8StringLength]) != 1) {
			unsigned long error = ERR_get_error();

			[self close];

			@throw [SSLConnectionFailedException
			    exceptionWithHost: host
					 port: port
				       socket: self
				     SSLError: error];
		}

		SSL_set_verify(_SSL, SSL_VERIFY_PEER, NULL);
	}

	SSL_set_connect_state(_SSL);

	encoding = [OFLocalization encoding];

	if ((_privateKeyFile != nil && !SSL_use_PrivateKey_file(_SSL,
	    [_privateKeyFile cStringWithEncoding: encoding],
	    SSL_FILETYPE_PEM)) || (_certificateFile != nil &&
	    !SSL_use_certificate_file(_SSL, [_certificateFile
	    cStringWithEncoding: encoding],
	    SSL_FILETYPE_PEM))) {
		unsigned long error = ERR_get_error();

		[super close];

		@throw [SSLConnectionFailedException
		    exceptionWithHost: host
				 port: port
			       socket: self
			     SSLError: error];
	}

	if (SSL_connect(_SSL) != 1) {
		unsigned long error = ERR_get_error();
		long res;

		[super close];

		if ((res = SSL_get_verify_result(_SSL)) != X509_V_OK)
			@throw [SSLConnectionFailedException
			    exceptionWithHost: host
					 port: port
				       socket: self
				     SSLError: error
				 verifyResult: res];
		else
			@throw [SSLConnectionFailedException
			    exceptionWithHost: host
					 port: port
				       socket: self
				     SSLError: error];
	}
}

- (void)startTLSWithExpectedHost: (OFString*)host
{
	[self SSL_startTLSWithExpectedHost: host
				      port: 0];
}

- (void)connectToHost: (OFString*)host
		 port: (uint16_t)port
{
	[super connectToHost: host
			port: port];

	[self SSL_startTLSWithExpectedHost: host
				      port: port];
}

- (instancetype)accept
{
	SSLSocket *client = (SSLSocket*)[super accept];
	of_string_encoding_t encoding;

	if ((client->_SSL = SSL_new(ctx)) == NULL ||
	    !SSL_set_fd(client->_SSL, client->_socket)) {
		[client SSL_super_close];
		/* FIXME: Get a proper errno */
		@throw [OFAcceptFailedException exceptionWithSocket: self
							      errNo: 0];
	}

	if (_requestClientCertificatesEnabled)
		SSL_set_verify(client->_SSL, SSL_VERIFY_PEER, NULL);

	SSL_set_accept_state(client->_SSL);

	encoding = [OFLocalization encoding];

	if (!SSL_use_PrivateKey_file(client->_SSL, [_privateKeyFile
	    cStringWithEncoding: encoding],
	    SSL_FILETYPE_PEM) || !SSL_use_certificate_file(client->_SSL,
	    [_certificateFile cStringWithEncoding: encoding],
	    SSL_FILETYPE_PEM) || SSL_accept(client->_SSL) != 1) {
		[client SSL_super_close];
		/* FIXME: Get a proper errno */
		@throw [OFAcceptFailedException exceptionWithSocket: self
							      errNo: 0];
	}

	return client;
}

- (void)close
{
	if (_SSL != NULL)
		SSL_shutdown(_SSL);

	[super close];
}

- (void)SSL_super_close
{
	[super close];
}

- (size_t)lowlevelReadIntoBuffer: (void*)buffer
			  length: (size_t)length
{
	ssize_t ret;

	if (length > INT_MAX)
		@throw [OFOutOfRangeException exception];

	if (_socket == INVALID_SOCKET)
		@throw [OFNotOpenException exceptionWithObject: self];

	if (_atEndOfStream)
		@throw [OFReadFailedException exceptionWithObject: self
						  requestedLength: length
							    errNo: ENOTCONN];

	if ((ret = SSL_read(_SSL, buffer, (int)length)) < 0) {
		if (SSL_get_error(_SSL, ret) == SSL_ERROR_WANT_READ)
			return 0;

		@throw [OFReadFailedException exceptionWithObject: self
						  requestedLength: length];
	}

	if (ret == 0)
		_atEndOfStream = true;

	return ret;
}

- (void)lowlevelWriteBuffer: (const void*)buffer
		     length: (size_t)length
{
	if (length > INT_MAX)
		@throw [OFOutOfRangeException exception];

	if (_socket == INVALID_SOCKET)
		@throw [OFNotOpenException exceptionWithObject: self];

	if (_atEndOfStream)
		@throw [OFWriteFailedException exceptionWithObject: self
						   requestedLength: length
							     errNo: ENOTCONN];

	if (SSL_write(_SSL, buffer, (int)length) < length)
		@throw [OFWriteFailedException exceptionWithObject: self
						   requestedLength: length];
}

- (bool)hasDataInReadBuffer
{
	if (_SSL != NULL && SSL_pending(_SSL) > 0)
		return true;

	return [super hasDataInReadBuffer];
}

- (void)setCertificateFile: (OFString*)certificateFile
		forSNIHost: (OFString*)SNIHost
{
	/* TODO */
	OF_UNRECOGNIZED_SELECTOR
}

- (OFString*)certificateFileForSNIHost: (OFString*)SNIHost
{
	/* TODO */
	OF_UNRECOGNIZED_SELECTOR
}

- (void)setPrivateKeyFile: (OFString*)privateKeyFile
	       forSNIHost: (OFString*)SNIHost
{
	/* TODO */
	OF_UNRECOGNIZED_SELECTOR
}

- (OFString*)privateKeyFileForSNIHost: (OFString*)SNIHost
{
	/* TODO */
	OF_UNRECOGNIZED_SELECTOR
}

- (void)setPrivateKeyPassphrase: (const char*)privateKeyPassphrase
		     forSNIHost: (OFString*)SNIHost
{
	/* TODO */
	OF_UNRECOGNIZED_SELECTOR
}

- (const char*)privateKeyPassphraseForSNIHost: (OFString*)SNIHost
{
	/* TODO */
	OF_UNRECOGNIZED_SELECTOR
}

- (OFDataArray*)channelBindingDataWithType: (OFString*)type
{
	size_t length;
	char buffer[64];
	OFDataArray *data;

	if (![type isEqual: @"tls-unique"])
		@throw [OFInvalidArgumentException exception];

	if (SSL_session_reused(_SSL) ^ !_listening) {
		/*
		 * We are either client or the session has been resumed
		 * => we have sent the finished message
		 */
		length = SSL_get_finished(_SSL, buffer, 64);
	} else {
		/* peer sent the finished message */
		length = SSL_get_peer_finished(_SSL, buffer, 64);
	}

	data = [OFDataArray dataArray];
	[data addItems: buffer
		 count: length];

	return data;
}

- (X509Certificate*)peerCertificate
{
	X509 *certificate = SSL_get_peer_certificate(_SSL);

	if (!certificate)
		return nil;

	return [[[X509Certificate alloc]
	    initWithX509Struct: certificate] autorelease];
}

- (void)verifyPeerCertificate
{
	unsigned long ret;

	if (SSL_get_peer_certificate(_SSL) != NULL) {
		if ((ret = SSL_get_verify_result(_SSL)) != X509_V_OK) {
			const char *tmp = X509_verify_cert_error_string(ret);
			OFString *reason = [OFString stringWithUTF8String: tmp];
			@throw [SSLInvalidCertificateException
			    exceptionWithReason: reason];
		}
	} else
		@throw [SSLInvalidCertificateException
		    exceptionWithReason: @"No certificate"];
}
@end
