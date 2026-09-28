/*
 * Rule: PRE02-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE02-C violation
 *
 * The list opens one more parenthesis than it closes, so the | is inside
 * no pair the list completes: the text after the expansion closes it, and
 * BIT(6) | BIT(7) is no longer grouped as the definition intends.
 */

#define BIT(n) (1u << (n))
#define CALIBRATION_MASK ((unsigned) (BIT(6) | BIT(7)) /* VIOLATION */

unsigned mask(void)
{
    return 0;
}
