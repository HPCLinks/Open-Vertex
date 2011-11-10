/*
 * Copyright (C) 2007 by Latchesar Ionkov <lucho@ionkov.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * LATCHESAR IONKOV AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <stdio.h>
#include <fcntl.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "spfs.h"
#include "libxauth.h"

struct Xkey {
	RSA*	key;
};

static int decode_base64(u8 *src, int slen, char *dst);

static int
print_hexa(char *label, void *s, int buflen)
{
	int i;
	unsigned char *buf;

	buf = s;
	fprintf(stderr, "%s:", label);
	for(i = 0; i < buflen; i++)
		fprintf(stderr, "%02x:", buf[i]);
	fprintf(stderr, "\n");
	return 0;
}

Xkey *
xauth_pubkey_create(char *buf, int buflen)
{
	int n;
	u32 elen, nlen, slen;
	u8 *skey, *skeyptr;
	u8 *eptr, *nptr;
	BIGNUM *ebn, *nbn;
	Xkey *ret;

	if (strncmp(buf, "ssh-rsa ", 8) != 0) {
		sp_werror("invalid key type", EIO);
		return NULL;
	}

	slen = strlen(buf + 8);
	skeyptr = skey = sp_malloc(slen + 1);
	if (!skey)
		return NULL;

	n = decode_base64((u8 *) (buf + 8), slen, skey);
	if (n < 4)
		goto error;

	skey += 7+4;
	n -= 7+4;
	elen = (skey[0]<<24) | (skey[1]<<16) | (skey[2]<<8) | skey[3];
	if (elen+8 > n)
		goto error;

	eptr = (u8 *)skey + 4;
	nlen = (skey[elen+4]<<24) | (skey[elen+5]<<16) | (skey[elen+6]<<8) | 
		skey[elen+7];
//	nlen = *((u32 *) (eptr + elen));
	if (elen + nlen + 8 > n)
		goto error;

	nptr = eptr + elen + 4;
//	print_hexa("key", skey, n);
//	print_hexa("e", eptr, elen);
//	print_hexa("n", nptr, nlen);
	ebn = BN_bin2bn(eptr, elen, NULL);
	nbn = BN_bin2bn(nptr, nlen, NULL);

	ret = sp_malloc(sizeof(*ret));
	if (!ret) {
		free(skey);
		return NULL;
	}

	ret->key = RSA_new();
	ret->key->e = ebn;
	ret->key->n = nbn;

	return ret;

error:
	free(skeyptr);
	sp_werror("invalid key", EIO);
	return NULL;
}

Xkey *
xauth_privkey_create(char *filename)
{
	char err[128];
	Xkey *ret;
	FILE *f;

	if (!filename)
		return xauth_user_privkey();

	f = fopen(filename, "r");
	if (!f) {
		sp_suerror(filename, errno);
		return NULL;
	}

	ret = sp_malloc(sizeof(*ret));
	if (!ret) {
		fclose(f);
		return NULL;
	}

	ret->key = PEM_read_RSAPrivateKey(f, NULL, NULL, "RSA private key");
	fclose(f);
	if (!ret->key) {
		ERR_error_string_n(ERR_get_error(), err, sizeof(err));
		sp_werror("%s: %s", EIO, filename, err);
		free(ret);
		return NULL;
	}

	return ret;
}

Xkey *
xauth_pubkey_create_from_file(char *filename)
{
	int n, fd;
	char *buf;
	Xkey *ret;

	if (!filename)
		return xauth_user_pubkey();

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		sp_suerror(filename, errno);
		return NULL;
	}

	ret = sp_malloc(sizeof(*ret));
	if (!ret) {
		close(fd);
		return NULL;
	}

	n = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	buf = sp_malloc(n);
	if (!buf) {
		close(fd);
		free(ret);
		return NULL;
	}

	n = read(fd, buf, n);
	if (n < 0) {
		close(fd);
		free(ret);
		free(buf);
		sp_suerror(filename, errno);
		return NULL;
	}
	close(fd);

	ret = xauth_pubkey_create(buf, n);
	free(buf);
	return ret;
}

void 
xauth_destroy(Xkey *xkey)
{
	if (xkey->key)
		RSA_free(xkey->key);

	free(xkey);
}

Xkey *
xauth_user_pubkey(void)
{
	int n;
	struct passwd pw, *pwp;
	int bufsize;
	char *buf, kname[1024];

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize < 256)
		bufsize = 256;

	buf = sp_malloc(bufsize);
	if (!buf)
		return NULL;

	n = getpwuid_r(geteuid(), &pw, buf, bufsize, &pwp);
	if (n) {
		sp_uerror(n);
		free(buf);
		return NULL;
	}

	snprintf(kname, sizeof(kname), "%s/.ssh/id_rsa.pub", pw.pw_dir);
	free(buf);
	return xauth_pubkey_create_from_file(kname);
}

int 
xauth_pubkey_encrypt(u8 *src, int slen, u8 *dst, int dlen, Xkey *xkey)
{
	int n, csize, len;
	char err[128];

	len = 0;
	csize = RSA_size(xkey->key) - 12;
	while (slen > 0) {
		n = slen>csize?csize:slen;
		if ((n+12) > dlen) {
			sp_werror("destination too small", EIO);
			return -1;
		}

		n = RSA_public_encrypt(n, src, dst, xkey->key, RSA_PKCS1_PADDING);
		if (n < 0) {
			ERR_error_string_n(ERR_get_error(), err, sizeof(err));
			sp_werror(err, EIO);
			return -1;
		}

		src += n;
		slen -= n;
		dst += n;
		dlen -= n;
		len += n;
	}

	return len;
}

Xkey *
xauth_user_privkey(void)
{
	int n;
	struct passwd pw, *pwp;
	int bufsize;
	char *buf, kname[256];

        bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize < 256)
                bufsize = 256;

        buf = sp_malloc(bufsize);
        if (!buf)
                return NULL;
		
        n = getpwuid_r(geteuid(), &pw, buf, bufsize, &pwp);
        if (n) {
                sp_uerror(n);
                free(buf);
                return NULL;
        }
        snprintf(kname, sizeof(kname), "%s/.ssh/id_rsa", pw.pw_dir);
        free(buf);
	return xauth_privkey_create(kname);
}

int
xauth_privkey_decrypt(u8 *src, int slen, u8 *dst, int dlen, Xkey *xkey)
{
	int n, csize, len;
	char err[128];

	len = 0;
	csize = RSA_size(xkey->key);

	while (slen > 0) {
		n = slen>csize?csize:slen;
		if (n > dlen) {
			sp_werror("destination too small", EIO);
			return -1;
		}

		n = RSA_private_decrypt(slen, src, dst, xkey->key, RSA_PKCS1_PADDING);
		if (n < 0) {
			ERR_error_string_n(ERR_get_error(), err, sizeof(err));
			sp_werror(err, EIO);
			return -1;
		}

		src += csize;
		slen -= csize;
		dst += n;
		dlen -= n;
		len += n;
	}

	return len;
}

int
xauth_sign(u8 *buf, int buflen, u8 *sig, int siglen, Xkey *xkey)
{
	unsigned int n, rsize;
	u8 hash[SHA_DIGEST_LENGTH];
	u8 *sign;
	char err[128];

	SHA1(buf, buflen, hash);
	rsize = RSA_size(xkey->key);
	sign = sp_malloc(rsize);
	if (!sign)
		return -1;

	if (!RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sign, &n, xkey->key)) {
		ERR_error_string_n(ERR_get_error(), err, sizeof(err));
		sp_werror(err, EIO);
		free(sign);
		return -1;
	}

	if (n > siglen) {
		sp_werror("destination too small", EIO);
		free(sign);
		return -1;
	}

	memmove(sig, sign, n);
	free(sign);

	return n;
}

int
xauth_verify(u8 *buf, int buflen, u8 *sig, int siglen, Xkey *xkey)
{
	int ret;
	u8 hash[SHA_DIGEST_LENGTH];

	SHA1(buf, buflen, hash);
	ret = RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH, sig, siglen, xkey->key);
	return ret;
}

int
xauth_hash(u8 *buf, int buflen, u8 *hash, int hashlen)
{
	if (hashlen < SHA_DIGEST_LENGTH) {
		sp_werror("buffer too small", EIO);
		return -1;
	}

	SHA1(buf, buflen, hash);
	return SHA_DIGEST_LENGTH;
}

int
xauth_rand(u8 *buf, int buflen)
{
	RAND_pseudo_bytes(buf, buflen);
	return 0;
}

static u8 a2d[256] = {
   255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
   255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
   255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,255,255,255,
   255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
   255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
   255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
   255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
   255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
   255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
   255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
   255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
   255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
   255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255
};

static int
decode_base64(u8 *src, int slen, char *dst)
{
	int i;
	u32 v;
	char *s;
	unsigned char c;

	s = dst;
	i = 0;
	v = 0;
	while (slen-- > 0) {
		c = a2d[*(src++)];
		if (c == 255)
			continue;

		switch (i) {
		case 0:
			v = c<<18;
			break;

		case 1:
			v |= c<<12;
			break;

		case 2:
			v |= c<<6;
			break;

		case 3:
			v |= c;
			*(dst++) = v>>16;
			*(dst++) = v>>8;
			*(dst++) = v;
			i = -1;
			break;
		}

		i++;
	}

	if (i == 2)
		*(dst++) = v<<16;
	else if (i == 3) {
		*(dst++) = v<<16;
		*(dst++) = v<<8;
	}

	return dst - s;
}
