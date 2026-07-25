/*
 * Rule: EXP33-C
 * Source: testcases (task 320 follow-up)
 * Status: PASS - Should NOT trigger EXP33-C violation
 * Description: `switch(5)` can never match `case 6:`, so `default:` is the
 * only reachable arm and unconditionally initializes `data` -- the CFG must
 * prune the non-matching constant case, mirroring the dead-branch pruning
 * already done for `if`/`while`/`for` on compile-time-constant conditions.
 * Modeled on Juliet's CWE457 flow-variant-15 (`switch(6)`/`switch(7)`)
 * goodG2B1 pattern.
 */

void print_int(int i);

void constant_switch_default_only(void) {
    int data;
    switch (5) {
    case 6:
        break;
    default:
        data = 5;
        break;
    }
    print_int(data);
}
