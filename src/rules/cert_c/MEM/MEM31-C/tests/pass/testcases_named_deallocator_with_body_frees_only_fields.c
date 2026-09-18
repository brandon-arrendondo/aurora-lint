/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * A callee whose NAME is shaped like a deallocator but whose BODY is right
 * here and frees only fields of its parameter, never the parameter itself.
 * The wrapper that forwards the object to it is credited with freeing it on
 * the strength of that name alone -- a guess, kept so leak reports stay
 * quiet -- and a guess must not ACCUSE: the owner's one real free after the
 * wrapper is a teardown pair, not a double free. curl's Curl_close ->
 * Curl_req_free(&data->req, data) -> Curl_client_cleanup(data), and
 * hostap's wpa_supplicant_deinit_iface -> wpa_supplicant_cleanup(wpa_s) ->
 * free_hw_features(wpa_s), were both this (task 1269).
 */
#include <stdlib.h>

struct modes {
    int *channels;
};

struct iface {
    struct modes hw;
    char *name;
};

/* `free_` prefix, but the body releases a field, not `s`. */
static void free_hw_features(struct iface *s) {
    if (s->hw.channels == NULL)
        return;
    free(s->hw.channels);
    s->hw.channels = NULL;
}

/* `_cleanup` suffix, forwards `s` to a name-shaped helper with a body. */
static void iface_cleanup(struct iface *s) {
    free_hw_features(s);
    free(s->name);
    s->name = NULL;
}

void iface_deinit(struct iface *s) {
    iface_cleanup(s);
    free(s);
}
