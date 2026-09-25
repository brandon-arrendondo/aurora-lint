/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: PASS - a scanf scanset %[...] is a valid conversion (C11
 * 7.21.6.2p12) taking a char * argument. Its body is the set, so nothing in
 * it is parsed as more directive, and a ']' first in the set (after '[' or
 * '[^') is a member of the set, not its end.
 */

#include <stdio.h>

void read_line(FILE *fp) {
    char line[256];

    fscanf(fp, "%[^\n]s", line);
}

void read_quoted(const char *text) {
    char name[129];

    sscanf(text, "%128[^\"]", name);
}

void read_bracket_sets(const char *text) {
    char a[32];
    char b[32];
    int n;

    sscanf(text, "%[]abc]", a);
    sscanf(text, "%[^]x]", b);
    sscanf(text, "%31[^%]%d", a, &n);
    sscanf(text, "%*[ \t]%31s", b);
}
