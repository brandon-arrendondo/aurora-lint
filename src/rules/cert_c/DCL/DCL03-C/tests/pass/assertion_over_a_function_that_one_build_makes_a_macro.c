/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: PASS - An assertion over a function call is a runtime one, whatever a macro makes it elsewhere
 *
 * `holds_mutex` is a function, and only a build without threads makes it
 * a macro for `1`. In the builds that call it, the condition is evaluated
 * at run time, so no static assertion can replace the assertion.
 */
#include <assert.h>

int holds_mutex(void *db);
#ifdef NO_THREADS
#define holds_mutex(db) 1
#endif

void check(void *db)
{
    assert(holds_mutex(db));
}
