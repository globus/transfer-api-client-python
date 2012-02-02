#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/lhash.h>

#define SERIAL_RAND_BITS	64

int rand_serial(BIGNUM *b, ASN1_INTEGER *ai);
STACK_OF(X509) * read_cert_chain(BIO *input);
int write_proxy(BIO *bio_public_key, BIO *bio_issuer_credential, BIO *bio_out,
                BIO *bio_err, long valid_hours);


int main(int argc, char **argv) {
    BIO *bio_stdin = NULL;
    BIO *bio_stdout = NULL;
    BIO *bio_stderr = NULL;

    int rval = 1;
    long hours = 0;

    // TODO: take proxy file path as arg
    if (argc > 1) {
        // TODO: error check
        hours = strtol(argv[1], NULL, 10);
    } else {
        hours = 1;
    }

    // Setup IO
    if ((bio_stdin = BIO_new(BIO_s_file())) == NULL) {
        printf("Failed to allocate bio_stdin\n");
        goto end;
    }
    if ((bio_stdout = BIO_new(BIO_s_file())) == NULL) {
        printf("Failed to allocate bio_stdout\n");
        goto end;
    }
    if ((bio_stderr = BIO_new(BIO_s_file())) == NULL) {
        printf("Failed to allocate bio_stderr\n");
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

    return rval;
}


int write_proxy(BIO *bio_public_key, BIO *bio_issuer_credential, BIO *bio_out,
                BIO *bio_err, long valid_hours) {
    int i, rval = 1;
    X509V3_CTX ctx;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *issuer_pkey = NULL;
    X509 *issuer = NULL;
    const EVP_MD *digest = EVP_sha1();
    X509 *cert = NULL;
    STACK_OF(X509) *chain = NULL;
    X509_NAME *issuer_name = NULL, *subject_name = NULL;
    //X509V3_CTX ext_ctx;
    BIGNUM *serial_bn;
    char *serial_decimal = NULL;
    X509_EXTENSION *pci_ext = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    LHASH_OF(CONF_VALUE) *lhash = NULL;
#else
    LHASH *lhash = NULL;
#endif

    //int key_type = -1;

    // Read pubkey from stdin
    pkey = PEM_read_bio_PUBKEY(bio_public_key, NULL, NULL, NULL);
    if (pkey == NULL) {
        BIO_printf(bio_err, "failed to read PUBKEY\n");
        goto end;
    }

    // TODO: read from file instead?
    // Read issuer cert from stdin
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

    // Debug stuff
    /*
    key_type = EVP_PKEY_type(pkey->type);
    if (key_type == EVP_PKEY_RSA) {
        BIO_printf(bio_err, "key_type = EVP_PKEY_RSA\n");
    } else if (key_type == NID_undef) {
        BIO_printf(bio_err, "key_type = NID_undef\n");
    } else {
        BIO_printf(bio_err, "unknown key type\n");
    }
    */

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

    // add serial to subject
    // TODO: detect old proxy and use "proxy" as CN instead of serial number,
    // and don't add extensions
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
    if (!X509_NAME_add_entry_by_NID(subject_name, NID_commonName, MBSTRING_ASC,
                                    serial_decimal, -1, -1, 0)) {
        BIO_printf(bio_err, "Failed to add serial to subject name\n");
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

    // Causes warning on 1.0 but lh_CONF_VALUE_new doesn't work.
    lhash = lh_new(NULL, NULL);
    X509V3_set_conf_lhash(&ctx, lhash);
    pci_ext = X509V3_EXT_conf(lhash, &ctx, "proxyCertInfo",
                              "critical,language:Inherit all");
    X509_add_ext(cert, pci_ext, 0);
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
    rval = 0;

end:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (cert != NULL)
        X509_free(cert);
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
    if (lhash != NULL)
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        lh_CONF_VALUE_free(lhash);
#else
        lh_free(lhash);
#endif
    if (pci_ext != NULL)
        OPENSSL_free(pci_ext);
    return rval;
}


// Free return value with sk_X509_pop_free(chain, X509_free) if not NULL
STACK_OF(X509) * read_cert_chain(BIO *input) {
    STACK_OF(X509) * chain = NULL;
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
