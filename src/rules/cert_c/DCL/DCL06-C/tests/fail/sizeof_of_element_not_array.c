/*
 * Rule: DCL06-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL06-C violation
 */

/*
 * Rule: DCL06-C - Use meaningful symbolic constants
 * Status: FAIL
 * Reason: `sizeof buf[0]` and `sizeof *p` measure an ELEMENT, not the
 *         array, so they do not document the array's extent; a struct member
 *         array nobody takes sizeof of is still a magic size. An earlier fix.
 */

struct cfg {
    char name[64];
};

static struct cfg g;
static int table[300];

int count(void)
{
    return (int)(sizeof table[0]) + (int)g.name[0];
}
