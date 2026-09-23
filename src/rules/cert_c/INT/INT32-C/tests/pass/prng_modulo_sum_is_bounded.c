/*
 * Rule: INT32-C
 * Source: real-world (valkey src/fuzzer_command_generator.c:474 `60 * (1 +
 *         rand() % 60)`, :475 `1 + rand() % 10000`, src/lolwut6.c:104,
 *         src/listpack.c:1325 `(rand() % total_count) * 2`)
 * Status: PASS - Should NOT trigger INT32-C violation
 * Reason: `rand() % k` is `[0, k - 1]` once `rand()` is bounded by its
 *         contract, so a constant plus or times it is a small, fully
 *         resolved range and `result_fits_destination` proves it. The
 *         provenance gate still treats `rand()` as a value the program does
 *         not control -- correctly, since `1 + rand()` with no `%` really
 *         can reach `RAND_MAX + 1` (see the FAIL twin); the fix is the
 *         RANGE, not the provenance.
 */

#include <stdlib.h>

int generate(void)
{
    int period = 60 * (1 + rand() % 60);
    int count = 1 + rand() % 10000;
    int small = (rand() % 3) + 1;
    int mixed = rand() % 16 + 10;
    return period + count + small + mixed;
}
