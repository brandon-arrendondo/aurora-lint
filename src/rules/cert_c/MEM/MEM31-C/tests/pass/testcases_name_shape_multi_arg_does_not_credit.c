/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: curl's Curl_cwriter_free(data, writer) shape, an earlier fix. The
 * name-shape tier of a summary's frees_params exists for a callee with no
 * body in the scan, so it is a guess. When SEVERAL arguments name parameters
 * the name says nothing about WHICH one is released; crediting both makes
 * this wrapper's summary claim it frees the handle it merely passes through,
 * and the caller's own `free(data)` then reads as a double free. The writer
 * is still credited here -- through the literal free the engine can see --
 * so declining the ambiguous guess costs no leak coverage.
 */

#include <stdlib.h>

struct easy {
    int magic;
};

struct writer {
    int kind;
};

/* No body in this translation unit: the name shape is the only evidence. */
void writer_release(struct easy *data, struct writer *w);

static void writer_free(struct easy *data, struct writer *w)
{
    writer_release(data, w);
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
