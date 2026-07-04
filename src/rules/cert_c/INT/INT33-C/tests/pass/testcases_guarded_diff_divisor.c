/*
 * Rule: INT33-C
 * Source: testcases
 * Status: PASS - Difference-of-bounds divisor guarded by a relational check
 * Reason: mosquitto src/bridge.c rand_between()-style idiom; when the caller
 * (or an enclosing guard) proves high > low, `high - low` cannot be zero.
 */

int rand_between_guarded(int low, int high) {
    if (high > low) {
        return (high - low) / 2 + low;
    }
    return low;
}

int rand_between_early_return(int low, int high) {
    if (high <= low) {
        return low;
    }
    return (high - low) % 7;
}
