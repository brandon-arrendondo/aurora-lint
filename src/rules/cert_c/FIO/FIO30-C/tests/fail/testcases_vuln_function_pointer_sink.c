/*
 * Rule: FIO30-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO30-C violation
 */

/*
 * Rule: FIO30-C - Exclude user input from format strings
 * Status: FAIL
 * Reason: User input reaches a static sink called only through a local
 * function pointer (Juliet flow variant 44).
 */

#include <stdio.h>

static void show(char *fmt)
{
    printf(fmt);
}

void entry(void)
{
    char buf[100] = "";
    void (*print_it)(char *) = show;
    fgets(buf, sizeof(buf), stdin);
    print_it(buf);
}
