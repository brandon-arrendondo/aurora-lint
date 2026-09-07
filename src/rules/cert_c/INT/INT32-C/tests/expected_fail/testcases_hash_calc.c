/*
 * Rule: INT32-C
 * Source: testcases
 * Status: EXPECTED FAIL, by measurement rather than oversight. The overflow is
 * definite only across loop iterations -- the accumulator exceeds the band
 * after many passes, not at any single evaluation. VRA carries per-node
 * ranges, which cannot express that, so no definite-overflow check can prove
 * it and a possible-overflow check would flag every accumulator loop.
 * Genuine violation; kept as evidence.
 */

/*
 * Rule: INT32-C - Ensure that operations on signed integers do not result in overflow
 * Status: EXPECTED FAIL
 * Reason: Hash calculation using multiplication can overflow
 */

#include <limits.h>
#include <stdio.h>

int simple_hash(const char* str) {
    int hash = 1;
    int multiplier = 31;

    for (const char* p = str; *p; p++) {
        // VIOLATION: multiplication can overflow
        hash = hash * multiplier + *p;
    }

    return hash;
}

int main() {
    const char* test_strings[] = {
        "short",
        "this_is_a_longer_string_that_might_cause_overflow",
        "verylongstringthatcouldcauseoverflowinhashcalculation"
    };

    int count = sizeof(test_strings) / sizeof(test_strings[0]);

    for (int i = 0; i < count; i++) {
        int hash = simple_hash(test_strings[i]);
        printf("Hash of '%s': %d\n", test_strings[i], hash);
    }

    return 0;
}