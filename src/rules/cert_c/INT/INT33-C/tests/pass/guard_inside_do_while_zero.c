/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - The guard inside do { } while (0) runs once, before the
 * division
 */

int ratio(int a, int d)
{
    do {
        if (d == 0)
            return 0;
    } while (0);
    return a / d;
}
