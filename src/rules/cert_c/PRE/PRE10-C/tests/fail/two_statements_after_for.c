/*
 * Rule: PRE10-C
 * Source: aurora-lint
 * Status: FAIL - a macro that expands to a loop and a second statement
 *
 * FOR_EACH is a single for statement. TICK_THEN_TOCK is a for statement
 * followed by a call, so under an unbraced if only the loop is conditional.
 */
void tick(void);
void tock(void);

#define FOR_EACH(i, n) for ((i) = 0; (i) < (n); (i)++)
#define TICK_THEN_TOCK(n) for (int k_ = 0; k_ < (n); k_++) tick(); tock()

void run(int n, int go) {
    int i;
    FOR_EACH(i, n) tick();
    if (go)
        TICK_THEN_TOCK(n);
}
