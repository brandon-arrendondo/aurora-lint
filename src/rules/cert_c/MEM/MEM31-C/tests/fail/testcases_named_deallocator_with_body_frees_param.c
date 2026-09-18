/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * Counterpart to testcases_named_deallocator_with_body_frees_only_fields.c:
 * when the name-shaped callee's body really does free its parameter, that
 * fact must still reach the forwarding wrapper's summary -- through the
 * body, not the name -- so the owner's second free is reported.
 */
#include <stdlib.h>

struct iface {
    char *name;
};

/* `_free` suffix AND a body that releases `s` itself. */
static void iface_free(struct iface *s) {
    free(s->name);
    free(s);
}

static void iface_cleanup(struct iface *s) {
    iface_free(s);
}

void iface_deinit(struct iface *s) {
    iface_cleanup(s);
    free(s); /* VIOLATION: iface_cleanup already released s */
}
