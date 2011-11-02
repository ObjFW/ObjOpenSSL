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

#include <openssl/crypto.h>
#include <openssl/x509v3.h>

#import "X509Certificate.h"

#import <ObjFW/OFAutoreleasePool.h>
#import <ObjFW/OFArray.h>
#import <ObjFW/OFDataArray.h>
#import <ObjFW/OFDictionary.h>
#import <ObjFW/OFFile.h>
#import <ObjFW/OFInitializationFailedException.h>
#import <ObjFW/OFInvalidEncodingException.h>
#import <ObjFW/OFList.h>
#import <ObjFW/OFMutableDictionary.h>
#import <ObjFW/OFString.h>

@implementation X509Certificate
- initWithFile: (OFString*)file
{
	self = [self init];

	@try {
		OFAutoreleasePool *pool = [[OFAutoreleasePool alloc] init];
		OFFile *fd = [OFFile fileWithPath: file
					     mode: @"r"];
		OFDataArray *data = [fd readDataArrayTillEndOfStream];
		[fd close];
		const unsigned char *dataCArray = [data cArray];
		crt = d2i_X509(NULL, &dataCArray, [data count]);
		[pool release];
		if (crt == NULL)
			@throw [OFInitializationFailedException
				    exceptionWithClass: isa];
	} @catch (id e) {
		[self release];
		@throw e;
	}

	return self;
}

- initWithX509Struct: (X509*)cert
{
	self = [self init];

	@try {
		crt = X509_dup(cert);
		if (crt == NULL)
			@throw [OFInitializationFailedException
				    exceptionWithClass: isa];
	} @catch (id e) {
		[self release];
		@throw e;
	}

	return self;
}

- (void)dealloc
{
	[issuer release];
	[subject release];
	[subjectAlternativeName release];

	if (crt != NULL)
		X509_free(crt);

	[super dealloc];
}

- (OFString*)description
{
	OFMutableString *ret = nil;//[OFMutableString string];

	[ret appendFormat: @"Issuer: %@\n\n", [self issuer]];
	[ret appendFormat: @"Subject: %@\n\n", [self subject]];
	[ret appendFormat: @"SANs: %@", [self subjectAlternativeName]];

	[ret makeImmutable];
	return ret;
}

- (OFDictionary*)issuer
{
	if (issuer == nil) {
		X509_NAME *name = X509_get_issuer_name(crt);
		issuer = [[self X509_dictionaryFromX509Name: name] retain];
	}

	return issuer;
}

- (OFDictionary*)subject
{
	if (subject == nil) {
		X509_NAME *name = X509_get_subject_name(crt);
		subject = [[self X509_dictionaryFromX509Name: name] retain];
	}

	return subject;
}

- (OFDictionary*)subjectAlternativeName
{
	if (subjectAlternativeName != nil)
		return subjectAlternativeName;

	int i = -1, j;
	OFAutoreleasePool *pool = [[OFAutoreleasePool alloc] init];
	OFMutableDictionary *ret = [OFMutableDictionary dictionary];

	while ((i = X509_get_ext_by_NID(crt, NID_subject_alt_name, i)) != -1) {
		X509_EXTENSION *extension;
		STACK_OF(GENERAL_NAME) *values;
		int count;

		extension = X509_get_ext(crt, i);
		if (extension == NULL)
			break;

		values = X509V3_EXT_d2i(extension);
		if (values == NULL)
			break;

		count = sk_GENERAL_NAME_num(values);
		for (j = 0; j < count; j++) {
			GENERAL_NAME *generalName;

			generalName = sk_GENERAL_NAME_value(values, j);

			switch(generalName->type) {
			case GEN_OTHERNAME: {
				OTHERNAME *otherName = generalName->d.otherName;
				OFMutableDictionary *types;
				OFList *list;
				OFString *key;

				types = [ret objectForKey: @"otherName"];
				if (types == nil) {
					types
					    = [OFMutableDictionary dictionary];
					[ret setObject: types
						forKey: @"otherName"];
				}

				key = [self X509_stringFromASN1Object:
					otherName->type_id];
				list = [types objectForKey: key];
				if (list == nil) {
					list = [OFList list];
					[types setObject: list
						  forKey: key];
				}

				[list appendObject:
				    [self X509_stringFromASN1String:
					otherName->value->value.asn1_string]];
				break;
			}
			case GEN_EMAIL: {
				OFList *list;

				list = [ret objectForKey: @"rfc822Name"];
				if (list == nil) {
					list = [OFList list];
					[ret setObject: list
						forKey: @"rfc822Name"];
				}

				[list appendObject:
				    [self X509_stringFromASN1String:
					generalName->d.rfc822Name]];
				break;
			}
			case GEN_DNS: {
				OFList *list;

				list = [ret objectForKey: @"dNSName"];
				if (list == nil) {
					list = [OFList list];
					[ret setObject: list
						forKey: @"dNSName"];
				}
				[list appendObject:
				    [self X509_stringFromASN1String:
					generalName->d.dNSName]];
				break;
			}
			case GEN_URI: {
				OFList *list;

				list = [ret objectForKey:
					   @"uniformResourceIdentifier"];
				if (list == nil) {
					list = [OFList list];
					[ret setObject: list
						forKey:
						  @"uniformResourceIdentifier"];
				}
				[list appendObject:
				    [self X509_stringFromASN1String:
				    generalName->d.uniformResourceIdentifier]];
				break;
			}
			case GEN_IPADD: {
				OFList *list;

				list = [ret objectForKey: @"iPAddress"];
				if (list == nil) {
					list = [OFList list];
					[ret setObject: list
						forKey: @"iPAddress"];
				}
				[list appendObject:
				    [self X509_stringFromASN1String:
					generalName->d.iPAddress]];
				break;
			}
			default:
				break;
			}
		}

		i++; /* Next extension */
	}

	[ret makeImmutable];
	[ret retain];
	[pool release];

	return (subjectAlternativeName = ret);
}

- (BOOL)hasCommonNameMatchingDomain: (OFString*)domain
{
	OFString *name;
	OFAutoreleasePool *pool = [[OFAutoreleasePool alloc] init];
	OFList *CNs = [[self subject] objectForKey: OID_commonName];

	for (name in CNs) {
		if ([self X509_isAssertedDomain: name
				    equalDomain: domain]) {
			[pool release];
			return YES;
		}
	}

	[pool release];
	return NO;
}

- (BOOL)hasDNSNameMatchingDomain: (OFString*)domain
{
	OFString *name;
	OFAutoreleasePool *pool = [[OFAutoreleasePool alloc] init];
	OFDictionary *SANs = [self subjectAlternativeName];
	OFList *assertedNames = [SANs objectForKey: @"dNSName"];

	for (name in assertedNames) {
		if ([self X509_isAssertedDomain: name
				    equalDomain: domain]) {
			[pool release];
			return YES;
		}
	}

	[pool release];
	return NO;
}

- (BOOL)hasSRVNameMatchingDomain: (OFString*)domain
			 service: (OFString*)service
{
	size_t serviceLength;
	OFString *name;
	OFAutoreleasePool *pool = [[OFAutoreleasePool alloc] init];
	OFDictionary *SANs = [self subjectAlternativeName];
	OFList *assertedNames = [[SANs objectForKey: @"otherName"]
				     objectForKey: OID_SRVName];

	if (![service hasPrefix: @"_"])
		service = [service stringByPrependingString: @"_"];

	service = [service stringByAppendingString: @"."];
	serviceLength = [service length];

	for (name in assertedNames) {
		if ([name hasPrefix: service]) {
			OFString *asserted;
			asserted = [name substringWithRange:
				of_range(serviceLength,
					[name length] - serviceLength)];
			if ([self X509_isAssertedDomain: asserted
					    equalDomain: domain]) {
				[pool release];
				return YES;
			}
		}
	}

	[pool release];
	return NO;
}

- (BOOL) X509_isAssertedDomain: (OFString*)asserted
		   equalDomain: (OFString*)domain
{
	/*
	 * In accordance with RFC 6125 this only allows a wildcard as the
	 * left-most label and matches only the left-most label with it.
	 * E.g. *.example.com matches foo.example.com,
	 * but not foo.bar.example.com
	 */
	size_t firstDot;
	if (![asserted caseInsensitiveCompare: domain])
		return YES;

	if (![asserted hasPrefix: @"*."])
		return NO;

	asserted = [asserted substringWithRange: of_range(2,
			[asserted length] - 2)];

	firstDot = [domain indexOfFirstOccurrenceOfString: @"."];
	if (firstDot == OF_INVALID_INDEX)
		return NO;
	domain = [domain substringWithRange: of_range(firstDot + 1,
			[domain length] - firstDot - 1)];

	if (![asserted caseInsensitiveCompare: domain])
		return YES;

	return NO;
}

- (OFDictionary*)X509_dictionaryFromX509Name: (X509_NAME*)name
{
	int i;
	int count = X509_NAME_entry_count(name);
	OFAutoreleasePool *pool = [[OFAutoreleasePool alloc] init];
	OFMutableDictionary *dict = [OFMutableDictionary dictionary];

	for (i = 0; i < count; i++) {
		OFString *key, *value;
		X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, i);
		ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
		ASN1_STRING *str = X509_NAME_ENTRY_get_data(entry);
		key = [self X509_stringFromASN1Object: obj];

		if ([dict objectForKey: key] == nil)
			[dict setObject: [OFList list]
				 forKey: key];

		value = [self X509_stringFromASN1String: str];
		[[dict objectForKey: key] appendObject: value];
	}

	[dict makeImmutable];
	[dict retain];
	[pool release];

	return [dict autorelease];
}


- (OFString*)X509_stringFromASN1Object: (ASN1_OBJECT*)obj
{
	int len, buf_len = 256;
	char *buf = [self allocMemoryWithSize: buf_len];
	OFString *ret;
	while ((len = OBJ_obj2txt(buf, buf_len, obj, 1)) > buf_len) {
		buf_len = len;
		[self resizeMemory: buf
			    toSize: buf_len];
	}
	ret = [X509OID stringWithUTF8String: buf];
	[self freeMemory: buf];
	return ret;
}

- (OFString*) X509_stringFromASN1String: (ASN1_STRING*)str
{
	char *buf;
	OFString *ret;
	if (ASN1_STRING_to_UTF8((unsigned char**)&buf, str) < 0)
		@throw [OFInvalidEncodingException exceptionWithClass: isa];
	ret = [OFString stringWithUTF8String: buf];
	OPENSSL_free(buf);
	return ret;
}
@end

@implementation X509OID
- (OFString*)description
{
	char tmp[1024];
	OBJ_obj2txt(tmp, sizeof(tmp), OBJ_txt2obj(s->cString, 1), 0);
	return [OFString stringWithUTF8String: tmp];
}
@end
