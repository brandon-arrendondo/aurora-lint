/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: The summary builder's name-shape tier is a fallback "for a
 * callee with no body to read", and it never checked whether that was true.
 * curl's free_urlhandle(u) frees ten FIELDS of u and never u itself, but the
 * name matches `free_*`, so urlset_clear was credited with freeing its
 * parameter and propagate_transitive_frees carried that outward to
 * curl_url_set -- making every later curl_url_cleanup(uh) read as a double
 * free of a handle nothing had released. A name is not evidence when the body
 * is right there. An earlier fix.
 */

#include <stdlib.h>

struct urlhandle {
    char *scheme;
    char *user;
};

/* Frees the FIELDS, never the handle. */
static void free_urlhandle(struct urlhandle *u) {
    free(u->scheme);
    free(u->user);
    u->scheme = NULL;
    u->user = NULL;
}

static int urlset_clear(struct urlhandle *u) {
    free_urlhandle(u);
    return 0;
}

static int url_set(struct urlhandle *u) {
    return urlset_clear(u);
}

void reuse_handle_after_clearing_it(void) {
    struct urlhandle *uh = malloc(sizeof(*uh));
    if (!uh) {
        return;
    }
    uh->scheme = NULL;
    uh->user = NULL;
    url_set(uh);
    urlset_clear(uh);
    free(uh);
}

/* The pointee form of the same thing: the helper releases *pp, not pp. */
static void release_slot(char **pp) {
    free(*pp);
    *pp = NULL;
}

static void clear_slot(char **pp) {
    release_slot(pp);
}

void slot_owner_still_owns_its_own_pointer(void) {
    char **slots = malloc(sizeof(*slots) * 2);
    if (!slots) {
        return;
    }
    slots[0] = NULL;
    clear_slot(&slots[0]);
    free(slots);
}
