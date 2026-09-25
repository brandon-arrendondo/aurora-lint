/*
 * Rule: FIO30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO30-C violation
 */

/*
 * Rule: FIO30-C - Exclude user input from format strings
 * Status: PASS
 * Reason: A static sink called only through a local function pointer, and
 * only ever with a literal (Juliet flow variant 44's goodG2B). The call
 * through the pointer is a call to the function bound to it, so the sink
 * has an observed caller, and that caller is clean.
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
