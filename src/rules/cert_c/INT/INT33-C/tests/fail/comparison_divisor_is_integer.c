/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - Should trigger INT33-C violation
 *
 * A comparison has type int (C11 6.5.8p6) even when it compares doubles, so
 * this is integer division by a value that is 0 whenever d <= 0.5.
 */
int divide_by_comparison(int n, double d) {
    return n / (d > 0.5); // violation
}
