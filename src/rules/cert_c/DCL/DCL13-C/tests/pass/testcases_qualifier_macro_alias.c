/*
 * Rule: DCL13-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL13-C violation
 */

/*
 * Reason: without a preprocessor tree-sitter-c cannot know that Tcl's
 * `CONST` macro spells `const`, so the leading qualifier looks like an
 * unknown identifier -- is_const stays false and the pointer param would
 * be reported as "should be const" even though the source already says so.
 * The pre-parse pass (empty_macro_blank::substitute_qualifier_alias_macros)
 * rewrites `CONST` to `const` byte-length-preservingly, so tree-sitter
 * parses the qualifier correctly and is_const reads back true (task 758,
 * tools_sqc; real shape from sqlite src/tclsqlite.h:37 which defines the
 * macro and every ext/fts5/fts5_tcl.c parameter that uses it).
 */

#define CONST const

int consume_bytes(CONST unsigned char *buf, int n)
{
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += buf[i];
    }
    return sum;
}

int compare_strs(CONST char *a, CONST char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (int)((unsigned char)*a - (unsigned char)*b);
}
