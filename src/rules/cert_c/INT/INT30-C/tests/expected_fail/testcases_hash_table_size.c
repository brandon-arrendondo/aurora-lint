/*
 * Rule: INT30-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: the operand here is a function
 * parameter (or a local with no traced taint source), and INT30-C's opt-in
 * provenance gate (has_risky_operand_provenance, backed by int_provenance)
 * treats that as bounded local state, so the unsigned wrap is not
 * reported. That gate is what removes the bounded-counter false positives
 * on real code; flagging every unconstrained parameter is the noise it
 * exists to avoid. Detecting this needs caller-side bounds reasoning, not
 * a louder gate. The fixture is a genuine INT30-C violation and stays as
 * tracked evidence of the trade.
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: EXPECTED FAIL
 * Reason: Multiplication wrap in hash table allocation
 */

#include <stdlib.h>
#include <stddef.h>

struct entry {
    int key;
    void *value;
};

void create_hash_table(size_t num_buckets) {
    // Multiplication may wrap
    struct entry *table = malloc(num_buckets * sizeof(struct entry));  // Line 17 - VIOLATION

    if (table) {
        free(table);
    }
}

int main(void) {
    create_hash_table(SIZE_MAX / 4);  // Will wrap
    return 0;
}
