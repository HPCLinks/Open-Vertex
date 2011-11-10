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
typedef struct Xkey Xkey;

Xkey *xauth_pubkey_create(char *buf, int buflen);
Xkey *xauth_pubkey_create_from_file(char *filename);
Xkey *xauth_privkey_create(char *filename);
Xkey *xauth_user_pubkey(void);
Xkey *xauth_user_privkey(void);
void xauth_destroy(Xkey *);

int xauth_pubkey_encrypt(u8 *src, int slen, u8 *dst, int dlen, Xkey *);
int xauth_pubkey_decrypt(u8 *src, int slen, u8 *dst, int dlen, Xkey *);
int xauth_privkey_encrypt(u8 *src, int slen, u8 *dst, int dlen, Xkey *);
int xauth_privkey_decrypt(u8 *src, int slen, u8 *dst, int dlen, Xkey *);
int xauth_sign(u8 *buf, int buflen, u8 *sig, int siglen, Xkey *);
int xauth_verify(u8 *buf, int buflen, u8 *sig, int siglen, Xkey *);
int xauth_hash(u8 *buf, int buflen, u8 *hash, int hashlen);
int xauth_rand(u8 *buf, int buflen);

