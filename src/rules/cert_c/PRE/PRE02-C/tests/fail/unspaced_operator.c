/*
 * Rule: PRE02-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE02-C violation
 *
 * An operator needs no spaces around it to be one: 2 * TOTAL expands to
 * 2 * base+extra.
 */

int base;
int extra;

#define TOTAL base+extra /* VIOLATION */

int twice_total(void)
{
    return 2 * TOTAL;
}
