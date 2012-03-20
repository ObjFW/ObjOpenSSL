/*
 * Copyright (c) 2011, Jonathan Schleifer <js@webkeks.org>
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

#include <openssl/ssl.h>

#import <ObjFW/OFTCPSocket.h>

@class X509Certificate;

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
-  initWithSocket: (OFTCPSocket*)socket
   privateKeyFile: (OFString*)privateKeyFile
  certificateFile: (OFString*)certificateFile;
/* Change the return type */
- (SSLSocket*)accept;
- (void)setPrivateKeyFile: (OFString*)file;
- (OFString*)privateKeyFile;
- (void)setCertificateFile: (OFString*)file;
- (OFString*)certificateFile;
- (OFDataArray*)channelBindingDataWithType: (OFString*)type;
- (X509Certificate*)peerCertificate;
- (void)verifyPeerCertificate;
@end
