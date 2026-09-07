/*
 * Rule: ARR30-C
 * Source: task 1022 (whitespace-sensitive bounds recognition)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: the loop bounds the index with `<`, written without spaces around
 * the operator. The bounds verdict used to be a text-substring test on the
 * condition ("i <"), so this reported while the byte-for-byte identical
 * `i < n` did not -- the verdict depended on the project's spacing style
 * rather than on the code. mosquitto writes every event loop this way.
 */

struct ev { int x; };
int poll_n(void);

int unspaced_bound(void)
{
    struct ev events[64];
    int n = poll_n();
    int total = 0;
    for (int i = 0; i<n; i++) { total += events[i].x; }
    return total;
}
