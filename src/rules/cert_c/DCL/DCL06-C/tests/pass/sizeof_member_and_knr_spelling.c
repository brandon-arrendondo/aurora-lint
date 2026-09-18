/*
 * Rule: DCL06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL06-C violation
 */

/*
 * Rule: DCL06-C - Use meaningful symbolic constants
 * Status: PASS
 * Reason: An array whose extent the code takes with sizeof is the CERT
 *         wiki's own compliant shape. Two spellings of that sizeof were not
 *         recognized because the operand was read from the text between the
 *         parentheses: `sizeof buf` (no parentheses, valid C) and
 *         `sizeof(x.name)` (a struct member, whose declarator is a
 *         field_identifier the rule never matched). Task 1153, mechanisms 7
 *         and 8.
 */

#include <string.h>

struct cfg {
    char name[64];
    char host[256];
};

static struct cfg g;
static char buf[128];
static char line[512];

void reset(struct cfg *c)
{
    memset(g.name, 0, sizeof(g.name));
    memset(c->host, 0, sizeof c->host);
    memset(buf, 0, sizeof buf);
    memset(line, 0, sizeof (line));
}
