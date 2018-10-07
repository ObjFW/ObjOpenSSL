/*
 * Copyright (c) 2016, Jonathan Schleifer <js@heap.zone>
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

#import <ObjFW/OFConnectionFailedException.h>

OF_ASSUME_NONNULL_BEGIN

@class SSLSocket;

@interface SSLConnectionFailedException: OFConnectionFailedException
{
	unsigned long _SSLError;
	long _verifyResult;
}

@property (readonly, nonatomic) unsigned long SSLError;
@property (readonly, nonatomic) long verifyResult;

+ (instancetype)exceptionWithHost: (nullable OFString *)host
			     port: (uint16_t)port
			   socket: (id)socket OF_UNAVAILABLE;
+ (instancetype)exceptionWithHost: (nullable OFString *)host
			     port: (uint16_t)port
			   socket: (id)socket
			    errNo: (int)errNo OF_UNAVAILABLE;
+ (instancetype)exceptionWithHost: (OFString *)host
			     port: (uint16_t)port
			   socket: (SSLSocket *)socket
			 SSLError: (unsigned long)SSLError;
+ (instancetype)exceptionWithHost: (OFString *)host
			     port: (uint16_t)port
			   socket: (SSLSocket *)socket
			 SSLError: (unsigned long)SSLError
		     verifyResult: (long)verifyResult;
- (instancetype)initWithHost: (nullable OFString *)host
			port: (uint16_t)port
		      socket: (id)socket OF_UNAVAILABLE;
- (instancetype)initWithHost: (nullable OFString *)host
			port: (uint16_t)port
		      socket: (id)socket
		       errNo: (int)errNo OF_UNAVAILABLE;
- (instancetype)initWithHost: (OFString *)host
			port: (uint16_t)port
		      socket: (SSLSocket *)socket
		    SSLError: (unsigned long)SSLError;
- (instancetype)initWithHost: (OFString *)host
			port: (uint16_t)port
		      socket: (SSLSocket *)socket
		    SSLError: (unsigned long)SSLError
		verifyResult: (long)verifyResult OF_DESIGNATED_INITIALIZER;
@end

OF_ASSUME_NONNULL_END
