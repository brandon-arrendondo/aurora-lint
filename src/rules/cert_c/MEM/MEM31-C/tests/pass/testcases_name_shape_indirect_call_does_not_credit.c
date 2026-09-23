/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: curl sendf.c's `writer->cwt->do_close(data, writer)`.
 * The `_close` here belongs to a struct FIELD holding a function
 * pointer, not to a function: the spelling says nothing about which callee
 * actually runs, so it is not evidence for crediting either argument as
 * freed. Only a callee spelled as a plain identifier may be guessed at. The
 * writer's own free is still seen, so nothing leaks.
 */

#include <stdlib.h>

struct easy {
    int magic;
};

struct writer;

struct writer_type {
    void (*do_close)(struct easy *data, struct writer *w);
};

struct writer {
    const struct writer_type *cwt;
};

static void writer_free(struct easy *data, struct writer *w)
{
    w->cwt->do_close(data, w);
    free(w);
}

void use_writer(void)
{
    struct easy *data = malloc(sizeof(*data));
    struct writer *w;

    if (!data) {
        return;
    }
    w = malloc(sizeof(*w));
    if (!w) {
        free(data);
        return;
    }
    writer_free(data, w);
    free(data);
}
