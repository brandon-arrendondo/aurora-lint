/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * curl's Curl_safefree shape: a function-like macro that frees AND nulls
 * its argument, freeing through an object-like alias of free rather than
 * free itself. The rule read a free by three spellings -- literal free, a
 * callee whose summary frees its parameter, a name shaped like a
 * deallocator -- and this macro is none of them, so `Curl_safefree(no_proxy)`
 * at the tail of lib/url.c's create_conn_helper_init_proxy released nothing
 * as far as the rule could see and `no_proxy` was reported leaked at the
 * end of the function. The macro table already knows what the body does;
 * the rule now reads it, resolving the inner callee the same way it
 * resolves a direct call.
 *
 * A second safe-free is free(NULL), not a double free, and the tail free of
 * a pointer the branch already safe-freed is likewise a no-op. The macro
 * frees a field or an alias the same way a bare free() does: hostap's
 * `pos = buf; ... os_free(buf);` and curl's `Curl_safefree(service.value)`.
 */

#include <stdlib.h>

#define curlx_free free
#define Curl_safefree(ptr) do { curlx_free(ptr); (ptr) = NULL; } while(0)

extern int use(const char *s);

int freed_at_tail_by_macro(const char *s) {
    char *no_proxy = NULL;
    if (!s) {
        no_proxy = malloc(16);
    }
    Curl_safefree(no_proxy);
    return 0;
}

int safe_free_twice_is_not_double_free(void) {
    char *p = malloc(16);
    Curl_safefree(p);
    Curl_safefree(p);
    return 0;
}

int branch_safe_free_then_tail_free(int c) {
    char *p = malloc(16);
    if (c) {
        Curl_safefree(p);
    }
    free(p);
    return 0;
}

int label_frees_through_macro(int c) {
    char *p = malloc(16);
    if (c) {
        goto out;
    }
    use(p);
out:
    Curl_safefree(p);
    return 0;
}

struct blob { char *value; size_t length; };

int frees_a_field(int c) {
    struct blob service;
    int ret = 0;
    service.value = malloc(16);
    if (c) {
        ret = -1;
    }
    Curl_safefree(service.value);
    return ret;
}

int frees_through_an_alias(void) {
    char *buf = malloc(16);
    char *pos = buf;
    if (!buf) {
        return -1;
    }
    pos += 2;
    Curl_safefree(buf);
    return 0;
}
