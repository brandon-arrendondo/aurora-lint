/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: curl's `Curl_cwriter_free(data, writer)` and
 * `Curl_conn_close(data, sockindex)`, an earlier fix. Both are name-shaped
 * deallocators whose body hands the FIRST parameter to a call through a
 * function pointer, and neither releases it. An escape into an unreadable
 * call is not evidence that a release happened -- a callback reads its
 * argument and is spelled the same way -- so with a second parameter the
 * name cannot say which one it is about. The first version of the 1367 fix
 * credited param 0 anyway and reported curl's `data` as double-freed at
 * every one of these sites; only the SOLE parameter of a one-parameter
 * function may be guessed at.
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

/* Frees `w`, never `data` -- but `data` goes into the unreadable call. */
static void cwriter_free(struct easy *data, struct writer *w)
{
    w->cwt->do_close(data, w);
    free(w);
}

void add_writers(void)
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
    cwriter_free(data, w);
    free(data);
}
