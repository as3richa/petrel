#undef NDEBUG

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "algos.h"

#define N_BLOBS 2048
#define MAX_BLOB_LENGTH 8192

int main(int argc, char **argv) {
  srand(1337);

  const char *prefix = (argc <= 1) ? "." : argv[1];

  fputs("filename\t", stdout);
  for (size_t i = 0; i < N_ALGOS; i++) {
    fputs(algos[i].name, stdout);
    putchar((i == N_ALGOS - 1) ? '\n' : '\t');
  }

  for (size_t i = 0; i < N_BLOBS; i++) {
    unsigned char buffer[MAX_BLOB_LENGTH];
    const size_t len = rand() % MAX_BLOB_LENGTH;

    for (size_t j = 0; j < len; j++) {
      buffer[j] = rand() % 256;
    }

    char filename[100];
    assert(snprintf(filename, sizeof(filename), "%s/blob%zu.bin", prefix, i) <
           (int)sizeof(filename));

    FILE *file = fopen(filename, "wb");
    assert(file != NULL);
    assert(fwrite(buffer, 1, len, file) == len);
    assert(fclose(file) == 0);

    printf("%s\t", filename + strlen(prefix) + 1);

    for (size_t j = 0; j < N_ALGOS; j++) {
      unsigned char digest[64];
      hash(&algos[j], digest, buffer, len);
      for (size_t k = 0; k < algos[j].digest_len; k++) {
        printf("%02x", digest[k]);
      }

      putchar((j == N_ALGOS - 1) ? '\n' : '\t');
    }
  }

  return 0;
}