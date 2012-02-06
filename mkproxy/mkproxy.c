/*
 * Copyright 2012 University of Chicago (except where otherwise noted)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @file mkproxy.c
 * @Author Bryce Allen <ballen@ci.uchicago.edu>
 * @brief Program to create a proxy for use with the Globus Online Transfer API
 *        delegate_proxy activation method.
 *
 * This takes a public key returned by the Transfer API and a local X.509
 * credential and creates a proxy of the local credential using the provided
 * public key. The proxy includes the certificate chain, and can be passed
 * back to the API for activation. This is needed because the openssl tools
 * require a CSR to create certificates, and the API sends the bare public key
 * instead of a CSR.
 *
 * Building and Requirements:
 * Requires only gcc and openssl with headers. Tested with 0.9.8k and 1.0.0g,
 * but should work with any recent version.
 * @code
 *   gcc -o mkproxy mkproxy.c -lcrypto
 * @endcode
 *
 * Example Usage:
 * @code
 *   cat api_pubkey.pem /path/to/credential | mkproxy 10
 * @endcode
 * This creates a proxy certificate with a lifetime of 10 hours, using the
 * passed public key, issued by the passed credential, and prints the
 * certificate and chain as PEM to stdout.
 *
 * If no argument is passed to mkproxy, the default lifetime is 1 hour.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/conf.h>

#define SERIAL_RAND_BITS	64
#define LIMITED_PROXY_CN "limited proxy"
#define PROXY_CN "proxy"
#define USAGE "Usage: %s [lifetime in hours]\n"

int write_proxy(BIO *bio_public_key, BIO *bio_issuer_credential, BIO *bio_out,
                BIO *bio_err, long valid_hours);
STACK_OF(X509) * read_cert_chain(BIO *input);
int X509_NAME_ENTRY_get_text(X509_NAME_ENTRY *entry, char *buf, int len);
int rand_serial(BIGNUM *b, ASN1_INTEGER *ai);


int main(int argc, char **argv) {
    BIO *bio_stdin = NULL;
    BIO *bio_stdout = NULL;
    BIO *bio_stderr = NULL;

    int rval = EXIT_FAILURE;
    long hours = 0;
    char *endptr = "\1";

    // TODO: optionally take issuer file path as arg instead of reading stdin?
    if (argc == 1) {
        hours = 1;
    } else if (argc == 2) {
        hours = strtol(argv[1], &endptr, 10);
        if (*endptr != '\0') {
            fprintf(stderr, USAGE, argv[0]);
            return EXIT_FAILURE;
        }
    } else {
        fprintf(stderr, USAGE, argv[0]);
        return EXIT_FAILURE;
    }

    // Setup IO
    if ((bio_stdin = BIO_new(BIO_s_file())) == NULL) {
        fprintf(stderr, "Failed to allocate bio_stdin\n");
        goto end;
    }
    if ((bio_stdout = BIO_new(BIO_s_file())) == NULL) {
        fprintf(stderr, "Failed to allocate bio_stdout\n");
        goto end;
    }
    if ((bio_stderr = BIO_new(BIO_s_file())) == NULL) {
        fprintf(stderr, "Failed to allocate bio_stderr\n");
        goto end;
    }
    // TODO: can these fail?
    BIO_set_fp(bio_stdin, stdin, BIO_NOCLOSE);
    BIO_set_fp(bio_stdout, stdout, BIO_NOCLOSE|BIO_FP_TEXT);
    BIO_set_fp(bio_stderr, stderr, BIO_NOCLOSE|BIO_FP_TEXT);

    rval = write_proxy(bio_stdin, bio_stdin, bio_stdout, bio_stderr, hours);

end:
    if (bio_stdin != NULL)
        BIO_free(bio_stdin);
    if (bio_stdout != NULL)
        BIO_free(bio_stdout);
    if (bio_stderr != NULL)
        BIO_free(bio_stderr);

    return EXIT_SUCCESS;
}


/**
 * @brief Create and write a proxy certificate and chain using the public key
 *        and issuer credential from the passed BIOs, writing the output as
 *        PEM to the specified output BIO.
 *
 * @param [in] bio_public_key   Read public key to use in the proxy from this
 *                              BIO as PEM.
 * @param [in] bio_issuer_credential Read the issuer certificate,
 *                                   private key, and optional certificate
 *                                   chain from this BIO as PEM. Can be the
 *                                   same as bio_public_key, in which case
 *                                   the issuer credential will be read after
 *                                   the public key.
 * @param [in] bio_out Write the created proxy certificate and chain to this
 *                     BIO as PEM.
 * @param [in] bio_err Write error messages to this BIO.
 * @param [in] valid_hours Make the proxy certificate valid for this many hours
 *                         starting at the current time.
 *
 * @retval EXIT_SUCCESS Proxy successfully written to bio_out.
 * @retval EXIT_FAILURE An error occured and no proxy chain was written
 *                      to bio_out.
 */
int write_proxy(BIO *bio_public_key, BIO *bio_issuer_credential, BIO *bio_out,
                BIO *bio_err, long valid_hours) {
    int i, j, rval = EXIT_FAILURE;
    int old_proxy = 0;
    X509V3_CTX ctx;
    const EVP_MD *digest = EVP_sha1(); // does not require free
    char *subject_addition = NULL;
    char cn_buf[sizeof(LIMITED_PROXY_CN)] = { '\0' };
    X509_NAME_ENTRY *cn_entry = NULL;

    // free required
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *issuer_pkey = NULL;
    X509 *issuer = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *chain = NULL;
    X509_NAME *issuer_name = NULL, *subject_name = NULL;
    BIGNUM *serial_bn = NULL;
    char *serial_decimal = NULL;
    X509_EXTENSION *ext = NULL;
    CONF *conf = NULL;

    // Read pubkey from stdin
    pkey = PEM_read_bio_PUBKEY(bio_public_key, NULL, NULL, NULL);
    if (pkey == NULL) {
        BIO_printf(bio_err, "failed to read PUBKEY\n");
        goto end;
    }

    issuer = PEM_read_bio_X509(bio_issuer_credential, NULL, NULL, NULL);
    if (issuer == NULL) {
        BIO_printf(bio_err, "failed to read issuer cert\n");
        goto end;
    }
    issuer_pkey = PEM_read_bio_PrivateKey(bio_issuer_credential, NULL, NULL,
                                          NULL);
    if (issuer_pkey == NULL) {
        BIO_printf(bio_err, "failed to read issuer private key\n");
        goto end;
    }

    // Read the cert chain, if any.
    chain = read_cert_chain(bio_issuer_credential);
    if (chain == NULL) {
        BIO_printf(bio_err, "failed to read issuer chain\n");
        goto end;
    }

    // Create cert
    if ((cert = X509_new()) == NULL) {
        BIO_printf(bio_err, "Failed to allocate cert\n");
        goto end;
    }
    if (!X509_set_version(cert, 2)) {
        BIO_printf(bio_err, "Failed to set_version\n");
        goto end;
    }
    if (!rand_serial(NULL, X509_get_serialNumber(cert))) {
        BIO_printf(bio_err, "Failed to set random serial\n");
        goto end;
    }

    issuer_name = X509_NAME_dup(X509_get_subject_name(issuer));
    subject_name = X509_NAME_dup(issuer_name);

    // Check last CN in issuer name to see if it looks like an old proxy.
    i = -1;
    do {
        j = i;
        i = X509_NAME_get_index_by_NID(issuer_name, NID_commonName, i);
    } while (i != -1);
    if (j != -1) {
        cn_entry = X509_NAME_get_entry(issuer_name, j);
        X509_NAME_ENTRY_get_text(cn_entry, cn_buf, sizeof(cn_buf));
        if (strcmp(cn_buf, PROXY_CN) == 0
            || strcmp(cn_buf, LIMITED_PROXY_CN) == 0) {
            old_proxy = 1;
        }
    }

    // add serial or 'proxy' to subject
    if (old_proxy) {
        subject_addition = "proxy";
    } else {
        serial_bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
        if (!serial_bn) {
            BIO_printf(bio_err, "Failed to allocate BIGNUM for serial\n");
            goto end;
        }
        serial_decimal = BN_bn2dec(serial_bn);
        if (!serial_decimal) {
            BIO_printf(bio_err, "Failed convert bn serial to decimal string\n");
            goto end;
        }
        subject_addition = serial_decimal;
    }
    if (!X509_NAME_add_entry_by_NID(subject_name, NID_commonName, MBSTRING_ASC,
                                    subject_addition, -1, -1, 0)) {
        BIO_printf(bio_err, "Failed to add proxy/serial CN to subject name\n");
        goto end;
    }

    if (!X509_set_issuer_name(cert, issuer_name)) {
        BIO_printf(bio_err, "Failed to set issuer name\n");
        goto end;
    }
    // TODO: should we try to backdate for endpoints with clock skew?
    if (!X509_gmtime_adj(X509_get_notBefore(cert), 0)) {
        BIO_printf(bio_err, "Failed to set not before\n");
        goto end;
    }
    if (!X509_gmtime_adj(X509_get_notAfter(cert), 3600 * valid_hours)) {
        BIO_printf(bio_err, "Failed to set not after\n");
        goto end;
    }
    if (!X509_set_subject_name(cert, subject_name)) {
        BIO_printf(bio_err, "Failed to set subject_name\n");
        goto end;
    }
    if (!X509_set_pubkey(cert, pkey)) {
        BIO_printf(bio_err, "Failed to set pubkey\n");
        goto end;
    }

    conf = NCONF_new(NULL);
    if (conf == NULL) {
        BIO_printf(bio_err, "Failed to allocate nconf\n");
        goto end;
    }
    X509V3_set_nconf(&ctx, conf);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    if (old_proxy) {
        ext = X509V3_EXT_nconf(conf, &ctx, "keyUsage",
          "critical,Digital Signature, Key Encipherment, Data Encipherment");
    } else {
        ext = X509V3_EXT_nconf(conf, &ctx, "proxyCertInfo",
                               "critical,language:Inherit all");
    }
    if (ext == NULL) {
        BIO_printf(bio_err, "Failed to create extension\n");
        goto end;
    }
    X509_add_ext(cert, ext, 0);

    if (!X509_sign(cert, issuer_pkey, digest)) {
        BIO_printf(bio_err, "Failed to sign cert\n");
        goto end;
    }

    PEM_write_bio_X509(bio_out, cert);
    PEM_write_bio_X509(bio_out, issuer);
    for (i=0; i < sk_X509_num(chain); ++i) {
        PEM_write_bio_X509(bio_out, sk_X509_value(chain, i));
    }
    BIO_flush(bio_out);
    rval = EXIT_SUCCESS;

end:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (cert != NULL)
        X509_free(cert);
    if (issuer_pkey != NULL)
        EVP_PKEY_free(issuer_pkey);
    if (issuer != NULL)
        X509_free(issuer);
    if (chain != NULL)
        sk_X509_pop_free(chain, X509_free);
    if (issuer_name != NULL)
        X509_NAME_free(issuer_name);
    if (subject_name != NULL)
        X509_NAME_free(subject_name);
    if (serial_bn != NULL)
        BN_free(serial_bn);
    if (serial_decimal != NULL)
        OPENSSL_free(serial_decimal);
    if (conf != NULL)
        NCONF_free(conf);
    if (ext != NULL)
        OPENSSL_free(ext);
    return rval;
}


/**
 * @brief Read PEM X509 certificates from a BIO and return as a stack of X509.
 *
 * @param [in] bio  Open BIO to read from. If its already at EOF, an empty
 *                  stack will be returned. Should work with any file BIO,
 *                  including stdin.
 *
 * @retval NULL Error reading a X509 PEM. Could be caused by invalild PEM
 *              or non certificate PEM data.
 * @retval STACK_OF(X509)   The read certificates as a stack. Free with
 *                          sk_X509_pop_free(chain, X509_free).
 */
STACK_OF(X509) * read_cert_chain(BIO *input) {
    STACK_OF(X509) *chain = NULL;
    X509 *current_cert = NULL;
    int error = 0;

    chain = sk_X509_new_null();

    while (!BIO_eof(input)) {
        current_cert = PEM_read_bio_X509(input, NULL, NULL, NULL);
        if (current_cert == NULL) {
            // If the cert is NULL because we hit EOF, it's not an error.
            if (!BIO_eof(input)) {
                error = 1;
                goto end;
            }
        } else {
            sk_X509_push(chain, current_cert);
        }
    }

end:
    if (error && chain != NULL) {
        sk_X509_pop_free(chain, X509_free);
        chain = NULL;
    }
    return chain;
}


/**
 * @brief Get text of an X509_NAME_ENTRY into a char buffer.
 *
 * This fills an annoying gap in the openssl API. Text of an entry in an
 * X509_NAME can be fetched using X509_NAME_get_text_by_NID, but only the
 * first entry with that NID. The index of later entries can be determined
 * using X509_NAME_get_index_by_NID, but there is no method provided for
 * getting text at an index or from an X509_NAME_ENTRY. The following was
 * adapted from X509_NAME_get_text_by_OBJ in crypto/x509/x509name.c.
 *
 * @param [in] entry The entry to get text from.
 * @param [out] buf The buffer to copy text to, or NULL to get only the data
 *                  length.
 * @param [in] buf_size Size of the buffer in bytes. No more than this many
 *                      bytes will be copied into the buffer. Use sizeof to
 *                      be sure this is accurate.
 *
 * @retval The number of characters copied to the buffer, not including
 *         the null string terminator. If buf is NULL or buf_size < 1, the
 *         length of the data is returned instead and no data is copied.
 */
int X509_NAME_ENTRY_get_text(X509_NAME_ENTRY *entry, char *buf, int buf_size) {
    int copy_len;
    ASN1_STRING *data;

    data = X509_NAME_ENTRY_get_data(entry);
	copy_len = (data->length > (buf_size-1)) ? (buf_size-1) : data->length;
	if (buf == NULL || buf_size < 1)
        return (data->length);
	memcpy(buf, data->data, copy_len);
    buf[copy_len] = '\0';
    return copy_len;
}


/* Copied from openssl-0.9.8o apps/apps.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
int rand_serial(BIGNUM *b, ASN1_INTEGER *ai) {
	BIGNUM *btmp;
	int ret = 0;
	if (b)
		btmp = b;
	else
		btmp = BN_new();

	if (!btmp)
		return 0;

	if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0))
		goto error;
	if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
		goto error;

	ret = 1;
	
error:

	if (!b)
		BN_free(btmp);
	
	return ret;
}
