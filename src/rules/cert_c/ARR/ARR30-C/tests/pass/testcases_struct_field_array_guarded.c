/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Reason: a properly guarded struct-field array access
 * (`if (S.stackCounter < 32) { S.stack[S.stackCounter] = ...; }`) must
 * still be suppressed once the buffer is tracked (task 235) -- the fix
 * adds recall for the unguarded case without breaking correctly-guarded
 * accesses.
 */

typedef struct { int dummy; } Matrix;
typedef struct {
    int stackCounter;
    Matrix stack[32];
} State;

extern State S;

void rlPushMatrix(void)
{
    if (S.stackCounter < 32) {
        S.stack[S.stackCounter] = S.stack[0];
        S.stackCounter++;
    }
}
