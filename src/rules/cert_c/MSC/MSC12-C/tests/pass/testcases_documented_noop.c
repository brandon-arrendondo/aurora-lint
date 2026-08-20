/*
 * Rule: MSC12-C
 * Status: PASS - An empty FUNCTION body with an explanatory comment is a
 * documented no-op platform stub, not forgotten code. (Scoped to function
 * bodies only -- CERT's own wiki examples use the same "lone comment in
 * an otherwise-empty block" shape to illustrate an empty if/else/for
 * branch that SHOULD be flagged, so this exception does not extend
 * there.)
 */

void Arch_activateIdleThread(int tcb) {
    /* Don't need to do anything */
}
