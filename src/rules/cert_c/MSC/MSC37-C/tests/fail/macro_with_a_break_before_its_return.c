/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: FAIL - the `break` leaves the macro's `do` before its `return`, so
 * the macro does not return on every path and the break after it is reachable
 */

extern int flag;

#define STOP() do { if (flag) break; return -1; } while (0)

int f(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        STOP();
        break;
    }
}
