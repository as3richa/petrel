#undef NDEBUG

#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "algos.h"

struct buffer {
    unsigned char *data;
    size_t len;
    size_t cap;
};

const struct buffer empty_buffer = {NULL, 0, 0};
void buffer_push(struct buffer *buf, unsigned char byte);

int main(void) {
    struct buffer buf = empty_buffer;

    fputs("word\t", stdout);
    for(size_t i = 0; i < N_ALGOS; i++) {
        fputs(algos[i].name, stdout);
        putchar((i == N_ALGOS - 1) ? '\n' : '\t');
    }

    for(;;) {
        buf.len = 0;
        int c = getchar();

        if (c == EOF) {
            break;
        }

        if (isspace(c)) {
            continue;
        }

        do {
            buffer_push(&buf, c);
            c = getchar();
        } while (c != EOF && !isspace(c));

        for(size_t i = 0; i < buf.len; i++) {
            putchar(buf.data[i]);
        }
        putchar('\t');

        for(size_t i = 0; i < N_ALGOS; i ++) {
            unsigned char digest[64];
            hash(&algos[i], digest, buf.data, buf.len);

            for(size_t j = 0; j < algos[i].digest_len; j++) {
                printf("%02x", digest[j]);
            }

            putchar((i == N_ALGOS - 1) ? '\n' : '\t');
        }
    }

    return 0;
}

void buffer_push(struct buffer *buf, unsigned char byte) {
    assert(buf->len <= buf->cap);

    if (buf->len == buf->cap) {
        buf->cap = 2 * buf->cap + 16;
        buf->data = realloc(buf->data, buf->cap);
        assert(buf->data != NULL);
    }

    buf->data[buf->len++] = byte;
}