/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * Both arms of a preprocessor conditional free-and-null the same pointer
 * (mosquitto's http_api.c resolves a path with _fullpath under WIN32 and
 * realpath otherwise, and releases `filename` in each arm). The state
 * below the #endif is the union of what the arms end on; seeding it with
 * the state the chain was entered with re-admitted the allocation that
 * every arm had dropped, and reported it leaked at the end of the
 * function.
 */

#include <stdlib.h>
#include <limits.h>

#define mosquitto_free free
#define mosquitto_FREE(A) do { mosquitto_free(A); (A) = NULL; } while(0)

extern char *resolve_a(const char *in, char *out);
extern char *resolve_b(const char *in, char *out);

char *canonical(const char *url) {
    char *filename = malloc(64);
    char *canon;
    if (!filename) {
        return NULL;
    }
    canon = calloc(1, PATH_MAX);
    if (!canon) {
        mosquitto_FREE(filename);
        return NULL;
    }
#ifdef WIN32
    {
        char *resolved = resolve_a(filename, canon);
        mosquitto_FREE(filename);
        if (!resolved) {
            mosquitto_FREE(canon);
            return NULL;
        }
    }
#else
    {
        char *resolved = resolve_b(filename, canon);
        mosquitto_FREE(filename);
        if (!resolved) {
            mosquitto_FREE(canon);
            return NULL;
        }
    }
#endif
    return canon;
}
