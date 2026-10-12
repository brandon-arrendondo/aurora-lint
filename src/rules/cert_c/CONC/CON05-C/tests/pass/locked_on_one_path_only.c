/*
 * Rule: CON05-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON05-C violation
 *
 * The lock is taken and released inside a branch; the write after the
 * branch runs without it on every path.
 */

#include <stdio.h>
#include <threads.h>

mtx_t lock;
int counter;

void report(FILE *out, int bump) {
    if (bump) {
        mtx_lock(&lock);
        counter++;
        mtx_unlock(&lock);
    }
    fputs("done\n", out);
}
