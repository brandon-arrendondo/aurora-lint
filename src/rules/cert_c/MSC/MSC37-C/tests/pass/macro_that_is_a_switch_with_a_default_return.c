/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: PASS - a macro that is a switch whose default returns ends the arm
 */

#define FAIL(x) switch (x) { default: return -1; }

int g(int k, int x)
{
    switch (k) {
    case 1:
        return 1;
    default:
        FAIL(x);
        break;
    }
}
