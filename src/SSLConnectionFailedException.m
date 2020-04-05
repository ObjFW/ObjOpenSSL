/*
 * Copyright (c) 2016, Jonathan Schleifer <js@nil.im>
 *
 * https://git.nil.im/objopenssl.git
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

#include <inttypes.h>

#import <ObjFW/OFString.h>

#import "SSLConnectionFailedException.h"

#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wdocumentation"
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if defined(__clang__)
# pragma clang diagnostic pop
#endif

@implementation SSLConnectionFailedException
@synthesize SSLError = _SSLError, verifyResult = _verifyResult;

+ (instancetype)exceptionWithHost: (OFString *)host
			     port: (uint16_t)port
			   socket: (id)socket
{
	OF_UNRECOGNIZED_SELECTOR
}

+ (instancetype)exceptionWithHost: (OFString *)host
			     port: (uint16_t)port
			   socket: (id)socket
			    errNo: (int)errNo
{
	OF_UNRECOGNIZED_SELECTOR
}

+ (instancetype)exceptionWithHost: (OFString *)host
			     port: (uint16_t)port
			   socket: (SSLSocket *)socket
			 SSLError: (unsigned long)SSLError
{
	return [[[self alloc] initWithHost: host
				      port: port
				    socket: socket
				  SSLError: SSLError] autorelease];
}


+ (instancetype)exceptionWithHost: (OFString *)host
			     port: (uint16_t)port
			   socket: (SSLSocket *)socket
			 SSLError: (unsigned long)SSLError
		     verifyResult: (long)verifyResult
{
	return [[[self alloc] initWithHost: host
				      port: port
				    socket: socket
				  SSLError: SSLError
			      verifyResult: verifyResult] autorelease];
}

- initWithHost: (OFString *)host
	  port: (uint16_t)port
	socket: (id)socket
{
	OF_INVALID_INIT_METHOD
}

- initWithHost: (OFString *)host
	  port: (uint16_t)port
	socket: (id)socket
	 errNo: (int)errNo
{
	OF_INVALID_INIT_METHOD
}

- initWithHost: (OFString *)host
	  port: (uint16_t)port
	socket: (SSLSocket *)socket
      SSLError: (unsigned long)SSLError
{
	return [self initWithHost: host
			     port: port
			   socket: socket
			 SSLError: SSLError
		     verifyResult: 0];
}

- initWithHost: (OFString *)host
	  port: (uint16_t)port
	socket: (SSLSocket *)socket
      SSLError: (unsigned long)SSLError
  verifyResult: (long)verifyResult
{
	self = [super initWithHost: host
			      port: port
			    socket: socket
			     errNo: 0];

	_SSLError = SSLError;
	_verifyResult = verifyResult;

	return self;
}

- (OFString *)description
{
	if (_SSLError != SSL_ERROR_NONE) {
		char error[512];

		ERR_error_string_n(_SSLError, error, 512);

		if (_verifyResult != X509_V_OK)
			return [OFString stringWithFormat:
			    @"A connection to %@ on port %" @PRIu16 @" could "
			    @"not be established in socket of type %@: "
			    @"Verification failed: %s [%s]",
			    _host, _port, [_socket class],
			    X509_verify_cert_error_string(_verifyResult),
			    error];
		else
			return [OFString stringWithFormat:
			    @"A connection to %@ on port %" @PRIu16 @" could "
			    @"not be established in socket of type %@: %s",
			    _host, _port, [_socket class], error];
	}

	return super.description;
}
@end
