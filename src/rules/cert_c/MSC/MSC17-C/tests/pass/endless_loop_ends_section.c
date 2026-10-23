/*
 * Rule: MSC17-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger MSC17-C violation
 * Expect: default=clean strict=clean pedantic=clean
 *
 * A section ending in a loop that never ends cannot reach the next label:
 * `for (;;)` and `while (1)` with no break that leaves the loop. The break
 * inside the nested switch leaves only that switch.
 */
void work(int step);

void serve(int op)
{
    switch (op) {
    case 1:
        for (;;) {
            work(1);
        }
    case 2:
        while (1) {
            switch (op) {
            case 0:
                break;
            default:
                work(2);
                break;
            }
        }
    default:
        work(0);
        break;
    }
}
