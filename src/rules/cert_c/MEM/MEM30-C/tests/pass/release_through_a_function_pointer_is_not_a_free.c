/*
 * Rule: MEM30-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: sqlite's `sqlite3_free(void *p)` releases the block through
 * `sqlite3GlobalConfig.m.xFree(p)`, a call through a function POINTER that
 * no summary can follow, so nothing shows `amalg_free` releasing `a` and
 * the read after it is not reported. A use-after-free accusation needs a
 * free the analyzer can show; the wrapper's name is not one. Declaring
 * `amalg_free` as a deallocator makes the read a finding.
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

int read_after_release(void)
{
    char *a = malloc(64);

    if (a == NULL) {
        return 1;
    }
    a[0] = 'x';
    amalg_free(a);

    return a[0];
}
