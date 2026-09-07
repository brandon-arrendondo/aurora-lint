/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. A function-like macro
 * that forwards to a writer takes the output as `&var`, not as a bare
 * identifier. try_process_macro_output_params credited only a bare identifier
 * and then reported the call as handled, suppressing every later path -- so
 * arming that map for such a macro DROPPED credit the argument would otherwise
 * have got.
 *
 * pure-ftpd's `#define stat(A, B) fakestat(A, B)` is exactly this: harmless
 * while `fakestat` had no known output parameter, and a false positive at five
 * sites the moment library-call writes made one visible (task 1026). The macro
 * path now roots the argument the same way every other credit funnel does.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>

struct info {
    int a;
    int b;
};

extern int translate(char *out, size_t n, const char *in);

/* The forwarding target's only write through `out` is a library call, which
   is what puts it in the summary at all. */
static int real_get_info(const char *path, struct info *out)
{
    memset(out, 0, sizeof(*out));
    return path != NULL ? 0 : -1;
}

#define get_info(A, B) real_get_info(A, B)

void caller(const char *p)
{
    struct info info;

    if (get_info(p, &info) != 0) {
        return;
    }
    printf("%d %d\n", info.a, info.b);
}
