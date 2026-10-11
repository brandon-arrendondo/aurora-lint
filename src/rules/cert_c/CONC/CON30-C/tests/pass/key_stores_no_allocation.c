/*
 * Rule: CON30-C
 * Source: thread-API families (C11)
 * Status: PASS - Should NOT trigger CON30-C violation
 *
 * The key has no destructor, but nothing stored under it was allocated: the
 * address of a static object, a null pointer clearing the key (in two
 * spellings) and a string literal. There is nothing to free at thread exit.
 */

#include <threads.h>

static tss_t key;
static int counter;

int worker(void *arg) {
    (void)arg;
    tss_set(key, &counter);
    tss_set(key, "idle");
    tss_set(key, NULL);
    tss_set(key, (void *)0);
    return 0;
}

int start(void) {
    return tss_create(&key, NULL);
}
