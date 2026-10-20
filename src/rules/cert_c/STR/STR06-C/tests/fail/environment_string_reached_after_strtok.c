/*
 * Rule: STR06-C
 * Source: custom
 * Status: FAIL - Should trigger STR06-C violation
 * Description: Each environment string is used on a path that runs through
 * the strtok() call that tokenized it: a compound assignment, which reads the
 * pointer and leaves it in the tokenized string, a read after the if that
 * tokenizes it, a read in the case the tokenizing case falls through to, and
 * a read in another arm of a branch inside a loop, which the next iteration
 * reaches.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void compound_assignment(void) {
    char *p = getenv("PATH");
    strtok(p, ":");
    p += 1;
    puts(p);
}

void after_the_if(int c) {
    char *p = getenv("PATH");
    if (c) {
        strtok(p, ":");
    }
    puts(p);
}

void fall_through(int c) {
    char *p = getenv("PATH");
    switch (c) {
    case 1:
        strtok(p, ":");
        /* fall through */
    case 2:
        puts(p);
        break;
    }
}

void else_arm_in_a_loop(int n) {
    char *p = getenv("PATH");
    for (int i = 0; i < n; i++) {
        if (i == 0) {
            strtok(p, ":");
        } else {
            puts(p);
        }
    }
}

void other_case_in_a_loop(int c) {
    char *p = getenv("PATH");
    while (c--) {
        switch (c) {
        case 1:
            strtok(p, ":");
            break;
        case 2:
            puts(p);
            break;
        }
    }
}
