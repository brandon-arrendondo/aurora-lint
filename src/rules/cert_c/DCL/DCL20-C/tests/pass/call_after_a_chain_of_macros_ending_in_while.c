/*
 * Rule: DCL20-C
 * Source: aurora-lint
 * Status: PASS - the macro begins with another macro that expands to `while`
 */

#define WAIT_WHILE(c) while (c)
#define SPIN_UNTIL(c) WAIT_WHILE(!(c))

int ready(void);
void relax(void);

void wait_ready(void) {
    SPIN_UNTIL(ready()) relax();
}
