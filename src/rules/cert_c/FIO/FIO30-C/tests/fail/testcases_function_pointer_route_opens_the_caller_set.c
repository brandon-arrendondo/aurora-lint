/*
 * Rule: FIO30-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO30-C violation
 */

/*
 * Rule: FIO30-C - Exclude user input from format strings
 * Status: FAIL
 * Reason: A static sink called only through a function pointer, and only
 * ever with a literal (Juliet flow variant 44's goodG2B). Its address is
 * taken, so its caller set is open: ADR-0011 credits "every caller passes a
 * safe argument" only with no function-pointer route in, and the literal
 * the one visible call passes proves nothing about the parameter. The
 * format string is a parameter with no proof behind it.
 */

#include <stdio.h>

static void show(char *fmt)
{
    printf(fmt);
}

void entry(void)
{
    void (*print_it)(char *) = show;
    print_it("fixed text\n");
}
