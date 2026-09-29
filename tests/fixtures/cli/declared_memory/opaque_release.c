#include <stdlib.h>

struct mem_methods {
    void (*xFree)(void *);
};

static struct mem_methods g_methods;

/* Releases through a function pointer the analyzer cannot follow. */
void amalg_free(void *p)
{
    g_methods.xFree(p);
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

/* A library deallocator with no body in the scan. */
extern void lib_obj_free(void *p);

void hand_to_library(void)
{
    char *b = malloc(32);
    if (b == NULL) {
        return;
    }
    lib_obj_free(b);
}
