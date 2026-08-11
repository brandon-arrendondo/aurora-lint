/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Reason: a struct/union member array declared directly (not via an
 * array-typedef) was never tracked as a buffer at all -- a
 * `field_declaration` inside a struct body, unlike a top-level
 * `declaration`. An access through it (`S.stack[S.stackCounter]`) had no
 * buffer size to check against, so this was silently missed regardless of
 * whether the index was validated (task 235; real example: raylib's rlgl.h
 * `RLGL.State.stack[RL_MAX_MATRIX_STACK_SIZE]`, guarded by an `if` whose
 * then-branch only logs and does not return).
 */

#define N 32
typedef struct { int dummy; } Matrix;
typedef struct {
    int stackCounter;
    Matrix stack[N];
} State;

extern State S;

void rlPushMatrix(void)
{
    if (S.stackCounter >= N) { /* log only, no return */ }

    S.stack[S.stackCounter] = S.stack[0];
    S.stackCounter++;
}
