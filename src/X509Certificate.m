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

#import "X509Certificate.h"

#import <ObjFW/OFAutoreleasePool.h>
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

- initWithStruct: (X509*)cert
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
	if (crt != NULL)
		X509_free(crt);

	[super dealloc];
}

- (OFDictionary*)issuer
{
	X509_NAME *name = X509_get_issuer_name(crt);
	return [self X509_dictionaryFromX509Name: name];
}

- (OFDictionary*)subject
{
	X509_NAME *name = X509_get_subject_name(crt);
	return [self X509_dictionaryFromX509Name: name];
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
	ret = [OFString stringWithUTF8String: buf];
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
