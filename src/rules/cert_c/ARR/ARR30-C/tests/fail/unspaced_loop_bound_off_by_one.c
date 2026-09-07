/*
 * Rule: ARR30-C
 * Source: task 1022 (whitespace-sensitive bounds recognition)
 * Status: FAIL - SHOULD trigger ARR30-C violation
 * Reason: the companion to tests/pass/unspaced_loop_bound.c. `<=` admits
 * index == n, one past the end, and must stay a violation whether or not the
 * source puts spaces around the operator -- the node-based operator match has
 * to keep the unsafe case unsafe, not just quiet the safe one.
 */

struct ev { int x; };
int poll_n(void);

int unspaced_off_by_one(void)
{
    struct ev events[64];
    int n = poll_n();
    int total = 0;
    for (int i = 0; i<=n; i++) { total += events[i].x; }
    return total;
}
