/*
 * Copyright (c) 2011, Florian Zeitz <florob@babelmonkeys.de>
 *
 * https://webkeks.org/hg/objopenssl/
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

#include <openssl/x509.h>

#import <ObjFW/OFObject.h>
#import <ObjFW/OFString.h>
@class OFDictionary;

/* OIDs: */
#define OID_commonName @"2.5.4.3"
#define OID_surname @"2.5.4.4"
#define OID_serialNumber @"2.5.4.5"
#define OID_countryName @"2.5.4.6"
#define ID_localityName @"2.5.4.7"
#define OID_stateOrProvinceName @"2.5.4.8"
#define OID_streetAddress @"2.5.4.9"
#define OID_organizationName @"2.5.4.10"
#define OID_organizationalUnitName  @"2.5.4.11"

#define OID_SRVName @"1.3.6.1.5.5.7.8.7"

@interface X509Certificate: OFObject
{
	X509 *crt;
	OFDictionary *issuer;
	OFDictionary *subject;
	OFDictionary *subjectAlternativeName;
}

#ifdef OF_HAVE_PROPERTIES
@property (readonly) OFDictionary *issuer, *subject, *subjectAlternativeName;
#endif

- initWithFile: (OFString*)file;
- initWithX509Struct: (X509*)cert;
- (OFDictionary*)issuer;
- (OFDictionary*)subject;
- (OFDictionary*)subjectAlternativeName;
- (BOOL)hasCommonNameMatchingDomain: (OFString*)domain;
- (BOOL)hasDNSNameMatchingDomain: (OFString*)domain;
- (BOOL)hasSRVNameMatchingDomain: (OFString*)domain
			 service: (OFString*)service;
- (BOOL)X509_isAssertedDomain: (OFString*)asserted
		  equalDomain: (OFString*)domain;
- (OFDictionary*)X509_dictionaryFromX509Name: (X509_NAME*)name;
- (OFString*)X509_stringFromASN1Object: (ASN1_OBJECT*)obj;
- (OFString*)X509_stringFromASN1String: (ASN1_STRING*)str;
@end

@interface X509OID: OFObject <OFCopying>
{
	OFString *string;
}
@end
