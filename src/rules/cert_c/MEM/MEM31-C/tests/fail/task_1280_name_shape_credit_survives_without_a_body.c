/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The guard on task 1280's demotion. A name-shape free credit is
 * withdrawn only on POSITIVE evidence that the callee releases something
 * other than the parameter -- its fields or its pointee. It must still stand
 * when the callee has no body in the scan (the load-bearing sqlite3_free /
 * EVP_PKEY_free fallback), and when the callee's own body really does free
 * the parameter. Withdrawing either would turn every such wrapper's caller
 * into a false leak report.
 */

#include <stdlib.h>

struct handle {
    char *name;
};

/* No body anywhere in the scan: the name is the only evidence there is. */
extern void vendor_handle_free(struct handle *h);

void double_free_through_external_deallocator(void) {
    struct handle *h = malloc(sizeof(*h));
    if (!h) {
        return;
    }
    vendor_handle_free(h);
    vendor_handle_free(h);
}

/* Body present, and it genuinely frees the parameter itself. */
static void real_handle_free(struct handle *h) {
    free(h->name);
    free(h);
}

static void handle_destroy(struct handle *h) {
    real_handle_free(h);
}

void double_free_through_real_wrapper(void) {
    struct handle *h = malloc(sizeof(*h));
    if (!h) {
        return;
    }
    h->name = NULL;
    handle_destroy(h);
    free(h);
}
