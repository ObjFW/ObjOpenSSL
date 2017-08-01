/*
 * Copyright (c) 2011, 2013, 2015, Jonathan Schleifer <js@heap.zone>
 * Copyright (c) 2011, Florian Zeitz <florob@babelmonkeys.de>
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

#include <openssl/ssl.h>

#import <ObjFW/OFTCPSocket.h>
#import <ObjFW/OFTLSSocket.h>

OF_ASSUME_NONNULL_BEGIN

@class X509Certificate;

@interface SSLSocket: OFTCPSocket <OFTLSSocket>
{
	SSL *_SSL;
	id <OFTLSSocketDelegate> _delegate;
	OFString *_certificateFile, *_privateKeyFile;
	const char *_privateKeyPassphrase;
	bool _certificateVerificationEnabled;
	bool _requestClientCertificatesEnabled;
}

@property (nonatomic, getter=isRequestClientCertificatesEnabled)
    bool requestClientCertificatesEnabled;
@property OF_NULLABLE_PROPERTY (readonly, nonatomic)
    X509Certificate *peerCertificate;

- initWithSocket: (OFTCPSocket *)socket;
- (OFData *)channelBindingDataWithType: (OFString *)type;
- (nullable X509Certificate *)peerCertificate;
- (void)verifyPeerCertificate;
@end

OF_ASSUME_NONNULL_END
