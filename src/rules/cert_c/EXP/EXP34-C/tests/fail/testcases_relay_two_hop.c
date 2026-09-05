/*
 * Rule: EXP34-C
 * Source: testcases (Phase 4 regression)
 * Status: FAIL - NULL flows through a local variable relay to a callee
 *         that passes it onward (2-hop chain).
 *         prescan_single_tree aggregates call-site args and function summaries
 *         for intra-file inter-procedural analysis.
 */

#include <stdio.h>

void deep_sink(int *ptr) {
    *ptr = 200;
}

void relay(int *p) {
    deep_sink(p);
}

int main() {
    int *data = NULL;
    relay(data);
    return 0;
}
