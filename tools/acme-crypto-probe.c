/*
 * Every cryptographic operation RFC 8555 asks of an ACME client, and
 * nothing else. Built against a TLS library to answer one question: can
 * the acme process do its work with whatever the distribution shipped?
 *
 *   cc -o acme-crypto-probe acme-crypto-probe.c -lcrypto
 *
 * The API used here is the classic one on purpose. LibreSSL is a fork of
 * OpenSSL 1.0.2 and has no OSSL_PKEY_PARAM_* accessors; OpenSSL 3 still
 * has the classic ones unless it was configured no-deprecated. So the
 * intersection is what a portable client may spell, and this file is that
 * intersection.
 */
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void ok(const char *what, int good) {
  printf("%-58s %s\n", what, good ? "ok" : "FAILED");
  if (!good) failures++;
}

/* RFC 7515 appendix C: base64url, no padding. Every JWS field is spelled
   this way, and so is the certificate the CA hands back. */
static char *b64url(const unsigned char *in, size_t len) {
  static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  char *out = malloc(4 * ((len + 2) / 3) + 1);
  size_t o = 0;
  for (size_t i = 0; i < len; i += 3) {
    const unsigned n = (unsigned) in[i] << 16 | (i + 1 < len ? (unsigned) in[i + 1] << 8 : 0) |
                       (i + 2 < len ? in[i + 2] : 0);
    out[o++] = t[n >> 18 & 63];
    out[o++] = t[n >> 12 & 63];
    if (i + 1 < len) out[o++] = t[n >> 6 & 63];
    if (i + 2 < len) out[o++] = t[n & 63];
  }
  out[o] = '\0';
  return out;
}

/* RFC 8555 7.1: the account key and the certificate key. P-256 for both -
   ES256 is the only algorithm every ACME server must implement. */
static EVP_PKEY *keygen_p256(void) {
  EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (ec == NULL) return NULL;
  EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
  if (!EC_KEY_generate_key(ec)) { EC_KEY_free(ec); return NULL; }
  EVP_PKEY *pkey = EVP_PKEY_new();
  if (pkey == NULL || !EVP_PKEY_assign_EC_KEY(pkey, ec)) {
    EC_KEY_free(ec);
    EVP_PKEY_free(pkey);
    return NULL;
  }
  return pkey;
}

/* The public point, as the two coordinates a JWK spells separately. */
static int p256_xy(EVP_PKEY *pkey, unsigned char x[32], unsigned char y[32]) {
  EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
  if (ec == NULL) return 0;
  const EC_GROUP *g = EC_KEY_get0_group(ec);
  const EC_POINT *p = EC_KEY_get0_public_key(ec);
  BIGNUM *bx = BN_new(), *by = BN_new();
  int good = EC_POINT_get_affine_coordinates_GFp(g, p, bx, by, NULL) &&
             BN_bn2binpad(bx, x, 32) == 32 && BN_bn2binpad(by, y, 32) == 32;
  BN_free(bx);
  BN_free(by);
  EC_KEY_free(ec);
  return good;
}

/* RFC 7638: SHA-256 over the JWK's required members, lexicographic, no
   whitespace. This is what a challenge's key authorization is built on. */
static char *jwk_thumbprint(EVP_PKEY *pkey) {
  unsigned char x[32], y[32];
  if (!p256_xy(pkey, x, y)) return NULL;
  char *bx = b64url(x, 32), *by = b64url(y, 32);
  char json[256];
  const int n = snprintf(json, sizeof json,
                         "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", bx, by);
  free(bx);
  free(by);
  unsigned char md[SHA256_DIGEST_LENGTH];
  SHA256((const unsigned char *) json, (size_t) n, md);
  return b64url(md, sizeof md);
}

/* RFC 8555 6.2: every request is a JWS. ES256's signature is the raw
   R||S pair, 64 bytes - NOT the DER sequence EVP_DigestSign returns, and
   converting it is the client's job. */
static char *jws_es256(EVP_PKEY *pkey, const char *signing_input, size_t len) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  unsigned char *der = NULL;
  size_t derlen = 0;
  char *out = NULL;
  if (ctx == NULL) return NULL;
  if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) goto done;
  if (EVP_DigestSign(ctx, NULL, &derlen, (const unsigned char *) signing_input, len) != 1) goto done;
  der = malloc(derlen);
  if (EVP_DigestSign(ctx, der, &derlen, (const unsigned char *) signing_input, len) != 1) goto done;
  {
    const unsigned char *p = der;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long) derlen);
    if (sig == NULL) goto done;
    const BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG_get0(sig, &r, &s);
    unsigned char raw[64];
    if (BN_bn2binpad(r, raw, 32) == 32 && BN_bn2binpad(s, raw + 32, 32) == 32)
      out = b64url(raw, sizeof raw);
    ECDSA_SIG_free(sig);
  }
done:
  free(der);
  EVP_MD_CTX_free(ctx);
  return out;
}

/* The same signature, checked - a client that cannot verify its own JWS
   has not proven the pair works. */
static int jws_verify(EVP_PKEY *pkey, const char *input, size_t len, const unsigned char *raw) {
  ECDSA_SIG *sig = ECDSA_SIG_new();
  BIGNUM *r = BN_bin2bn(raw, 32, NULL), *s = BN_bin2bn(raw + 32, 32, NULL);
  ECDSA_SIG_set0(sig, r, s);
  unsigned char *der = NULL;
  const int derlen = i2d_ECDSA_SIG(sig, &der);
  int good = 0;
  if (derlen > 0) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    good = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
           EVP_DigestVerify(ctx, der, (size_t) derlen, (const unsigned char *) input, len) == 1;
    EVP_MD_CTX_free(ctx);
  }
  OPENSSL_free(der);
  ECDSA_SIG_free(sig);
  return good;
}

/* RFC 8555 7.4: the order is finalized with a PKCS#10 whose SAN names
   every identifier. The CN is not read by any CA that matters. */
static X509_REQ *csr_for(EVP_PKEY *pkey, const char *dnsnames) {
  X509_REQ *req = X509_REQ_new();
  if (req == NULL) return NULL;
  X509_REQ_set_version(req, 0);
  X509_NAME *name = X509_REQ_get_subject_name(req);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *) "example.org", -1,
                             -1, 0);
  X509_REQ_set_pubkey(req, pkey);

  STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
  X509_EXTENSION *san =
      X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, (char *) dnsnames);
  if (san == NULL) { sk_X509_EXTENSION_free(exts); X509_REQ_free(req); return NULL; }
  sk_X509_EXTENSION_push(exts, san);
  X509_REQ_add_extensions(req, exts);
  sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

  if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0) { X509_REQ_free(req); return NULL; }
  return req;
}

int main(void) {
  printf("OpenSSL/LibreSSL: %s\n\n", SSLeay_version(SSLEAY_VERSION));

  EVP_PKEY *account = keygen_p256();
  ok("an account key is generated (ES256, RFC 8555 7.1)", account != NULL);
  if (account == NULL) return 1;

  /* The key has to survive a restart, so it goes to disk and comes back. */
  BIO *mem = BIO_new(BIO_s_mem());
  int roundtrip = PEM_write_bio_PrivateKey(mem, account, NULL, NULL, 0, NULL, NULL) == 1;
  EVP_PKEY *reread = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
  ok("it survives PEM out and back in", roundtrip && reread != NULL);
  EVP_PKEY_free(reread);
  BIO_free(mem);

  char *thumb = jwk_thumbprint(account);
  ok("its JWK thumbprint is computed (RFC 7638)", thumb != NULL && strlen(thumb) == 43);

  /* RFC 8555 8.1: the key authorization a challenge answers with. http-01
     serves exactly this string, and needs nothing else from a TLS library. */
  char keyauth[256];
  const int kalen =
      snprintf(keyauth, sizeof keyauth, "%s.%s", "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ", thumb);
  ok("a key authorization is spelled (RFC 8555 8.1)", kalen > 44);

  /* dns-01 hashes it again; http-01 does not. Both stay in reach. */
  unsigned char kadigest[SHA256_DIGEST_LENGTH];
  SHA256((const unsigned char *) keyauth, (size_t) kalen, kadigest);
  char *dns01 = b64url(kadigest, sizeof kadigest);
  ok("and its digest, for dns-01 (RFC 8555 8.4)", dns01 != NULL && strlen(dns01) == 43);

  const char *protected_payload =
      "eyJhbGciOiJFUzI1NiIsIm5vbmNlIjoiNnM4M2VycUJ3IiwidXJsIjoiaHR0cHM6Ly9leGFtcGxlL25ldy1vcmRlciJ9"
      ".eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiZXhhbXBsZS5vcmcifV19";
  char *sigb64 = jws_es256(account, protected_payload, strlen(protected_payload));
  ok("a request is signed as a JWS (RFC 8555 6.2)", sigb64 != NULL && strlen(sigb64) == 86);

  /* Decode our own base64url back to the 64 raw bytes and check them. */
  int verified = 0;
  if (sigb64 != NULL) {
    unsigned char raw[64];
    static signed char rev[256];
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    memset(rev, -1, sizeof rev);
    for (int i = 0; i < 64; i++) rev[(unsigned char) t[i]] = (signed char) i;
    unsigned acc = 0;
    int bits = 0, o = 0;
    for (const char *p = sigb64; *p != '\0'; p++) {
      acc = acc << 6 | (unsigned) rev[(unsigned char) *p];
      bits += 6;
      if (bits >= 8) { bits -= 8; raw[o++] = (unsigned char) (acc >> bits); }
    }
    verified = o == 64 && jws_verify(account, protected_payload, strlen(protected_payload), raw);
  }
  ok("the ES256 signature is raw R||S and verifies", verified);

  EVP_PKEY *certkey = keygen_p256();
  ok("a certificate key is generated", certkey != NULL);

  X509_REQ *csr = csr_for(certkey, "DNS:example.org,DNS:www.example.org");
  ok("a CSR with a subjectAltName is built and signed (RFC 8555 7.4)", csr != NULL);
  ok("the CSR verifies against its own public key",
     csr != NULL && X509_REQ_verify(csr, certkey) == 1);

  unsigned char *csrder = NULL;
  const int csrlen = csr != NULL ? i2d_X509_REQ(csr, &csrder) : -1;
  char *csrb64 = csrlen > 0 ? b64url(csrder, (size_t) csrlen) : NULL;
  ok("and goes to the CA as base64url DER", csrb64 != NULL);

  printf("\n%s\n", failures == 0 ? "all ok - this library can run an ACME client"
                                 : "this library cannot run an ACME client");
  OPENSSL_free(csrder);
  free(csrb64);
  free(sigb64);
  free(dns01);
  free(thumb);
  X509_REQ_free(csr);
  EVP_PKEY_free(certkey);
  EVP_PKEY_free(account);
  return failures == 0 ? 0 : 1;
}
