/*
 * Rule: MEM30-C
 * Source: task 1289 (curl lib/url.c: url_create_needle(data) ->
 *         parseurlandfillconn(data, conn) -> up_free(data), then `data->set`
 *         at the caller; hostap wpa_supplicant_cleanup -> free_hw_features)
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * `up_free` is spelled like a deallocator and its body is right here: it
 * frees a FIELD of `data` and hands `data` back intact. The name-shape tier
 * guessed that `parse_and_fill(data)` frees `data`, the guess propagated to
 * its caller, and every later `data->x` was accused of use-after-free --
 * 310 MEM30-C findings across the corpus sat on such guesses, none labeled
 * TP. A body seen to release the object's parts and not the object
 * contradicts the name; the fold now declines the guess instead of
 * promoting it. Twin of the FAIL fixture, where the body says nothing.
 */
#include <stdlib.h>

struct easy {
    char *scheme;
    int retries;
};

/* `_free` suffix; releases a field of `data`, never `data`. */
static void up_free(struct easy *data)
{
    free(data->scheme);
    data->scheme = NULL;
}

static void parse_and_fill(struct easy *data)
{
    up_free(data); /* cleanup previous leftovers first */
}

int connect_easy(struct easy *data)
{
    parse_and_fill(data);
    return data->retries;
}
