/*
 * Rule: PRE10-C
 * Source: aurora-lint (misfire: a for header's semicolons counted as statements)
 * Status: PASS - Should NOT trigger PRE10-C violation
 *
 * Each macro expands to a single for statement. The two semicolons inside
 * a for header separate its clauses; they do not end statements.
 */
void tick(void);

#define FOR_EACH(i, n) for ((i) = 0; (i) < (n); (i)++)
#define REPEAT(n) for (int r_ = 0; r_ < (n); r_++) tick()
#define FOREVER for (;;)

void run(int n) {
    int i;
    FOR_EACH(i, n) tick();
    REPEAT(n);
    FOREVER { break; }
}
