/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - both functions allocate an array's elements in a loop and
 *         neither frees all of them: the first frees none, the second frees
 *         one fewer than it allocated.
 *
 * What this pins is not the detection but the LOCATION. Both findings used to
 * be reported at line 1, column 1 of whatever file they were found in -- a
 * literal in the reporting code, because the pattern matcher returned a
 * `bool` that was always true where the site belonged and nothing carried a
 * position. Line 1 names a construct that is not there, and every such
 * finding in one file collapsed onto the single key (file, 1, MEM31-C), which
 * is how eight distinct ones in a real file read as one.
 *
 * The generated fixture test only sees whether MEM31-C fires, so the line is
 * asserted in tests/cli_integration.rs from the per-site tags below. This
 * sentence deliberately does not spell the tag: the assertion counts the
 * lines carrying it, and a mention in prose would count as one of them.
 */

#include <stdlib.h>

#define SLOTS 8

void allocates_and_frees_nothing(int count)
{
    char *res[SLOTS];
    int i;

    for (i = 0; i < count; i++) {
        res[i] = malloc(16); /* LOOP-ALLOC-SITE */
    }
}

void frees_one_fewer_than_it_allocated(int count)
{
    char *res[SLOTS];
    int i;

    for (i = 0; i < count; i++) {
        res[i] = malloc(16); /* LOOP-ALLOC-SITE */
    }

    for (i = 0; i < count - 1; i++) {
        free(res[i]);
    }
}
