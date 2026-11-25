/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: two blocks each declare a `v`. The first is static, so the
 * string stored in `v.name` stays reachable after its return. The second is
 * automatic, and its string is lost at its return. The declaration each
 * store resolves to decides, not the name.
 * Expect: count=2
 */
#include <stdlib.h>
#include <string.h>

struct entry {
    char *name;
};

int remember(const char *name, int keep)
{
    if (keep) {
        static struct entry v;
        v.name = strdup(name);
        return 1;
    }
    {
        struct entry v;
        v.name = strdup(name); /* Expect: here */
        return 0; /* Expect: here */
    }
}
