/*
 * Copyright (c) 2011, Florian Zeitz <florob@babelmonkeys.de>
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
	OFMutableString *ret = [OFMutableString string];

	[ret appendFormat: @"Issuer: %@\n\n", [self issuer]];
	[ret appendFormat: @"Subject: %@\n\n", [self subject]];
	[ret appendFormat: @"SANs: %@", [self subjectAlternativeName]];

	[ret makeImmutable];
	return ret;
}

- (OFDictionary*)issuer
{
	X509_NAME *name;

	if (issuer != nil)
		return [[issuer copy] autorelease];

	name = X509_get_issuer_name(crt);
	issuer = [[self X509_dictionaryFromX509Name: name] retain];

	return issuer;
}

- (OFDictionary*)subject
{
	X509_NAME *name;

	if (subject != nil)
		return [[subject copy] autorelease];

	name = X509_get_subject_name(crt);
	subject = [[self X509_dictionaryFromX509Name: name] retain];

	return subject;
}

- (OFDictionary*)subjectAlternativeName
{
	OFAutoreleasePool *pool;
	OFMutableDictionary *ret;
	int i;

	if (subjectAlternativeName != nil)
		return [[subjectAlternativeName copy] autorelease];

	ret = [OFMutableDictionary dictionary];
	pool = [[OFAutoreleasePool alloc] init];

	i = -1;
	while ((i = X509_get_ext_by_NID(crt, NID_subject_alt_name, i)) != -1) {
		X509_EXTENSION *extension;
		STACK_OF(GENERAL_NAME) *values;
		int j, count;

		if ((extension = X509_get_ext(crt, i)) == NULL)
			break;

		if ((values = X509V3_EXT_d2i(extension)) == NULL)
			break;

		count = sk_GENERAL_NAME_num(values);
		for (j = 0; j < count; j++) {
			GENERAL_NAME *generalName;
			OFList *list;

			generalName = sk_GENERAL_NAME_value(values, j);

			switch(generalName->type) {
			case GEN_OTHERNAME:;
				OTHERNAME *otherName = generalName->d.otherName;
				OFMutableDictionary *types;
				X509OID *key;

				types = [ret objectForKey: @"otherName"];
				if (types == nil) {
					types =
					    [OFMutableDictionary dictionary];
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
			case GEN_EMAIL:
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
			case GEN_DNS:
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
			case GEN_URI:
				list = [ret objectForKey:
				    @"uniformResourceIdentifier"];
				if (list == nil) {
					list = [OFList list];
					[ret setObject: list
						forKey: @"uniformResource"
							@"Identifier"];
				}
				[list appendObject:
				    [self X509_stringFromASN1String:
				    generalName->d.uniformResourceIdentifier]];
				break;
			case GEN_IPADD:
				list = [ret objectForKey: @"iPAddress"];
				if (list == nil) {
					list = [OFList list];
					[ret setObject: list
						forKey: @"iPAddress"];
				}
				[list appendObject: [self
				    X509_stringFromASN1String:
				    generalName->d.iPAddress]];
				break;
			default:
				break;
			}
		}

		i++; /* Next extension */
		[pool releaseObjects];
	}

	[pool release];

	[ret makeImmutable];
	subjectAlternativeName = [ret retain];

	return ret;
}

- (BOOL)hasCommonNameMatchingDomain: (OFString*)domain
{
	OFString *name;
	OFAutoreleasePool *pool = [[OFAutoreleasePool alloc] init];
	OFList *CNs = [[self subject] objectForKey: OID_commonName];
	OFEnumerator *enumerator = [CNs objectEnumerator];

	while ((name = [enumerator nextObject]) != nil) {
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
	OFEnumerator *enumerator = [assertedNames objectEnumerator];

	while ((name = [enumerator nextObject]) != nil) {
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
	OFEnumerator *enumerator = [assertedNames objectEnumerator];

	if (![service hasPrefix: @"_"])
		service = [service stringByPrependingString: @"_"];

	service = [service stringByAppendingString: @"."];
	serviceLength = [service length];

	while ((name = [enumerator nextObject]) != nil) {
		if ([name hasPrefix: service]) {
			OFString *asserted;
			asserted = [name substringWithRange: of_range(
			    serviceLength, [name length] - serviceLength)];
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

- (BOOL)X509_isAssertedDomain: (OFString*)asserted
		  equalDomain: (OFString*)domain
{
	/*
	 * In accordance with RFC 6125 this only allows a wildcard as the
	 * left-most label and matches only the left-most label with it.
	 * E.g. *.example.com matches foo.example.com,
	 * but not foo.bar.example.com
	 */

	size_t firstDot;

	if ([asserted caseInsensitiveCompare: domain] == OF_ORDERED_SAME)
		return YES;

	if (![asserted hasPrefix: @"*."])
		return NO;

	asserted = [asserted substringWithRange:
	    of_range(2, [asserted length] - 2)];

	firstDot = [domain indexOfFirstOccurrenceOfString: @"."];
	if (firstDot == OF_INVALID_INDEX)
		return NO;

	domain = [domain substringWithRange:
	    of_range(firstDot + 1, [domain length] - firstDot - 1)];

	if (![asserted caseInsensitiveCompare: domain])
		return YES;

	return NO;
}

- (OFDictionary*)X509_dictionaryFromX509Name: (X509_NAME*)name
{
	OFMutableDictionary *dict = [OFMutableDictionary dictionary];
	OFAutoreleasePool *pool = [[OFAutoreleasePool alloc] init];
	int i, count = X509_NAME_entry_count(name);

	for (i = 0; i < count; i++) {
		X509OID *key;
		OFString *value;
		X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, i);
		ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
		ASN1_STRING *str = X509_NAME_ENTRY_get_data(entry);
		key = [self X509_stringFromASN1Object: obj];

		if ([dict objectForKey: key] == nil)
			[dict setObject: [OFList list]
				 forKey: key];

		value = [self X509_stringFromASN1String: str];
		[[dict objectForKey: key] appendObject: value];

		[pool releaseObjects];
	}

	[pool release];

	[dict makeImmutable];
	return dict;
}


- (X509OID*)X509_stringFromASN1Object: (ASN1_OBJECT*)object
{
	X509OID *ret;
	int length, bufferLength = 256;
	char *buffer = [self allocMemoryWithSize: bufferLength];

	@try {
		while ((length = OBJ_obj2txt(buffer, bufferLength, object,
		    1)) > bufferLength) {
			bufferLength = length;
			buffer = [self resizeMemory: buffer
					     toSize: bufferLength];
		}

		ret = [[[X509OID alloc]
		    initWithUTF8String: buffer] autorelease];
	} @finally {
		[self freeMemory: buffer];
	}

	return ret;
}

- (OFString*)X509_stringFromASN1String: (ASN1_STRING*)str
{
	OFString *ret;
	char *buffer;

	if (ASN1_STRING_to_UTF8((unsigned char**)&buffer, str) < 0)
		@throw [OFInvalidEncodingException exceptionWithClass: isa];

	@try {
		ret = [OFString stringWithUTF8String: buffer];
	} @finally {
		OPENSSL_free(buffer);
	}

	return ret;
}
@end

@implementation X509OID
- initWithUTF8String: (const char*) str
{
	self = [self init];

	@try {
		string = [[OFString alloc] initWithUTF8String: str];
	} @catch (id e) {
		[self release];
		@throw e;
	}

	return self;
}

- (void)dealloc
{
	[string release];
	[super dealloc];
}

- (OFString*)description
{
	char tmp[1024];
	OBJ_obj2txt(tmp, sizeof(tmp), OBJ_txt2obj([string UTF8String], 1), 0);
	return [OFString stringWithUTF8String: tmp];
}

- (BOOL)isEqual: (id)object
{
	if (([object isKindOfClass: [OFString class]]) ||
	    ([object isKindOfClass: [X509OID class]]))
		return [object isEqual: string];

	return NO;
}

- (uint32_t)hash
{
	return [string hash];
}

- copy
{
	return [self retain];
}
@end
