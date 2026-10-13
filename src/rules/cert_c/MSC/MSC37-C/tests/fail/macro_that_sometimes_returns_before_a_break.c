/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: FAIL under every preset
 *
 * `CHECK` returns only when its condition fails, so the `break` after it is
 * reachable when `k > 0`, and control then leaves the switch and falls off
 * the end of the function.
 */

#define CHECK(x) do { if (!(x)) return -1; } while (0)

int f(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        CHECK(k > 0);
        break;
    }
}
