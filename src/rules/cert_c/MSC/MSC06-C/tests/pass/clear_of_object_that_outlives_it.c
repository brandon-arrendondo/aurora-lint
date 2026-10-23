/*
 * Rule: MSC06-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger MSC06-C violation
 *
 * Clears that are not the last use of an object about to go out of scope,
 * so no compiler may drop them as dead stores: a static local, a file-scope
 * object, an extern object, a buffer of an enclosing block that is read
 * again after the inner block ends, and a buffer that a loop's next
 * iteration still holds. Each sits in its own function, so no
 * later statement in that function hides the case.
 */
#include <string.h>

static char file_buf[16];
extern char shared_buf[16];

void use(char *buf);

void static_local(void)
{
    static char kept[16];
    use(kept);
    memset(kept, 0, sizeof kept);
}

void file_scope(void)
{
    use(file_buf);
    memset(file_buf, 0, sizeof file_buf);
}

void extern_object(void)
{
    use(shared_buf);
    memset(shared_buf, 0, sizeof shared_buf);
}

void enclosing_block(void)
{
    char outer[16];
    {
        use(outer);
        memset(outer, 0, sizeof outer);
    }
    use(outer);
}

int more(void);

void loop_reuse(void)
{
    char buf[16];
    while (more()) {
        use(buf);
        memset(buf, 0, sizeof buf);
    }
}
