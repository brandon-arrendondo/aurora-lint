/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP34-C violation
 */

/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Status: FAIL
 * Reason: sqlite3_malloc64() returns NULL on OOM, exactly like malloc(), but
 * is a project-specific allocator wrapper rather than the stdlib name --
 * without recognizing the wrapper by name, sqc missed this exact live FN in
 * sqlite's own ext/misc/vfstrace.c:895-903 (task 173). The memset() call
 * dereferences pNew with no intervening NULL check.
 */

#include <stddef.h>

typedef unsigned long long sqlite3_uint64;
extern void *sqlite3_malloc64(sqlite3_uint64 n);

struct io_methods {
    int iVersion;
    void (*xClose)(void);
};

void make_methods(void)
{
    struct io_methods *pNew = sqlite3_malloc64(sizeof(*pNew));
    memset(pNew, 0, sizeof(*pNew));
    pNew->iVersion = 1;
}
