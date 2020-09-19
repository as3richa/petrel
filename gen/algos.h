#ifndef ALGOS_H
#define ALGOS_H

#include <openssl/evp.h>

#define N_ALGOS 7

struct algo {
  const char *name;
  const EVP_MD *(*md)(void);
  size_t digest_len;
};

static const struct algo algos[N_ALGOS] = {{"SHA1", EVP_sha1, 20},
                                           {"SHA256", EVP_sha256, 32},
                                           {"SHA224", EVP_sha224, 28},
                                           {"SHA512", EVP_sha512, 64},
                                           {"SHA384", EVP_sha384, 48},
                                           {"SHA512/224", EVP_sha512_224, 28},
                                           {"SHA512/256", EVP_sha512_256, 32}};

static void hash(const struct algo *algo, unsigned char *digest,
                 const unsigned char *str, size_t len) {
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  assert(context != NULL);
  assert(EVP_DigestInit_ex(context, algo->md(), NULL) == 1);
  assert(EVP_DigestUpdate(context, str, len) == 1);
  unsigned int digest_len = algo->digest_len;
  assert(EVP_DigestFinal_ex(context, digest, &digest_len) == 1);
  EVP_MD_CTX_free(context);
}

#endif