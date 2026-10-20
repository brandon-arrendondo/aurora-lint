/*
 * Rule: STR06-C
 * Source: custom
 * Status: PASS - Should NOT trigger STR06-C violation
 * Description: Each reference to the environment string after the strtok()
 * call in the text is one no path from the call reaches: the else arm of the
 * if that tokenizes it, another case of a switch whose case ends in break,
 * also when that case's body is braced, the other arm of an #if, and the
 * other arm of a ?:. A sizeof operand reads no string.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void else_arm(int c) {
    char *p = getenv("PATH");
    if (c) {
        strtok(p, ":");
    } else {
        puts(p);
    }
}

void other_case(int c) {
    char *p = getenv("PATH");
    switch (c) {
    case 1:
        strtok(p, ":");
        break;
    case 2:
        puts(p);
        break;
    }
}

void other_preprocessor_arm(void) {
    char *p = getenv("PATH");
#ifdef TOKENIZE
    strtok(p, ":");
#else
    puts(p);
#endif
}

void other_conditional_arm(int c) {
    char *p = getenv("PATH");
    const char *first = c ? strtok(p, ":") : p;
    puts(first);
}

void size_only(void) {
    char *p = getenv("PATH");
    char *t = strtok(p, ":");
    if (t && sizeof(p) > 4) {
        puts(t);
    }
}

void other_case_after_a_braced_body(int c) {
    char *p = getenv("PATH");
    switch (c) {
    case 1: {
        strtok(p, ":");
        break;
    }
    case 2:
        puts(p);
        break;
    }
}
