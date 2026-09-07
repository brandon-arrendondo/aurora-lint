/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: PASS - Compliant solution
 *
 * Wrapped in a function for the same reason as fail/wiki_dereference.c: at
 * file scope the rule declines to report anything, so the fragment form
 * passed without exercising the compliant-shape logic at all.
 */

void func(void) {
    int *p;
    /* ... */
    (*p)++;
}
