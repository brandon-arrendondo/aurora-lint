/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: a free credited on the deallocator's NAME alone is kept and
 * marked requires_manual_review. The mark has to reach every finding that
 * rests on such a free, not only a use-after-free read straight off the
 * freed name:
 *
 *   - a double free where either of the two frees is a name guess;
 *   - a use through a copy of a copy (`q = p; r = q;`, and the same
 *     through declarations), where the alias link is `r -> q`, not `r -> p`.
 *
 * Every function here is reported with or without the mark, so this file
 * only proves detection. The mark itself is asserted per line by
 * tests/cli_integration.rs: a line tagged MARKED must be reported with
 * requires_manual_review, a line tagged UNMARKED without it (both frees
 * there are plain `free`).
 */

#include <stdlib.h>

struct mem_methods {
    void (*xFree)(void *);
};

struct global_config {
    struct mem_methods m;
};

static struct global_config g_config;

void amalg_free(void *p)
{
    if (p == 0) {
        return;
    }
    g_config.m.xFree(p);
}

int both_frees_guessed(void)
{
    char *a = malloc(8);

    if (a == NULL) {
        return 1;
    }
    amalg_free(a);
    amalg_free(a); /* VIOLATION MARKED */
    return 0;
}

int prior_free_guessed(void)
{
    char *a = malloc(8);

    if (a == NULL) {
        return 1;
    }
    amalg_free(a);
    free(a); /* VIOLATION MARKED */
    return 0;
}

int current_free_guessed(void)
{
    char *a = malloc(8);

    if (a == NULL) {
        return 1;
    }
    free(a);
    amalg_free(a); /* VIOLATION MARKED */
    return 0;
}

int both_frees_read(void)
{
    char *a = malloc(8);

    if (a == NULL) {
        return 1;
    }
    free(a);
    free(a); /* VIOLATION UNMARKED */
    return 0;
}

int copied_twice_by_assignment(void)
{
    char *p = malloc(8);
    char *q;
    char *r;

    if (p == NULL) {
        return 1;
    }
    amalg_free(p);
    q = p;
    r = q;
    return r[0]; /* VIOLATION MARKED */
}

int copied_twice_by_declaration(void)
{
    char *p = malloc(8);

    if (p == NULL) {
        return 1;
    }
    amalg_free(p);
    char *q = p;
    char *r = q;
    return r[0]; /* VIOLATION MARKED */
}

int copied_twice_after_read_free(void)
{
    char *p = malloc(8);
    char *q;
    char *r;

    if (p == NULL) {
        return 1;
    }
    free(p);
    q = p;
    r = q;
    return r[0]; /* VIOLATION UNMARKED */
}
