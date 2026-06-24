// Repro for raylib rlPushMatrix() matrix-stack overflow (rlgl.h).
//
// The bug: the `stackCounter >= RL_MAX_MATRIX_STACK_SIZE` guard logs but has no
// `return`, so `RLGL.State.stack[stackCounter] = *currentMatrix` runs even when
// the stack is full. `stack` is `Matrix stack[RL_MAX_MATRIX_STACK_SIZE]` (32) and
// is followed in `RLGL.State` by `int stackCounter` (and more) — so the 33rd push
// writes `stack[32]`, i.e. ONE PAST the array, an INTRA-OBJECT overflow that
// clobbers the adjacent `stackCounter` (and following) members.
//
// Default ASan/valgrind do NOT flag intra-object overflows (verified), so this
// repro demonstrates the real consequence directly: it mirrors the exact field
// order from rlgl.h (Matrix stack[32]; int stackCounter; <next member>) and shows
// the 33rd push corrupts the neighbouring members instead of being rejected.
//
// Build/run:  cc -g repro_bug1.c -o repro_bug1 && ./repro_bug1   # asserts/aborts before fix
#include <string.h>
#include <stdio.h>
#include <assert.h>

#define RL_MAX_MATRIX_STACK_SIZE 32   // value from rlgl.h:225

typedef struct Matrix { float m0,m4,m8,m12, m1,m5,m9,m13, m2,m6,m10,m14, m3,m7,m11,m15; } Matrix; // 64 bytes

// Faithful prefix of RLGL.State field order (rlgl.h:1076-1083+):
//   Matrix *currentMatrix; ... Matrix stack[RL_MAX_MATRIX_STACK_SIZE]; int stackCounter; unsigned int currentTextureId; ...
struct {
    Matrix *currentMatrix;
    Matrix  transform;
    Matrix  stack[RL_MAX_MATRIX_STACK_SIZE];
    int     stackCounter;          // <-- &stack[32] aliases this member
    unsigned int currentTextureId; // next member, also in the 64-byte clobber range
} State;

// rlPushMatrix() logic verbatim (matrix-mode branch omitted; irrelevant to the overflow)
void rlPushMatrix(void)
{
    if (State.stackCounter >= RL_MAX_MATRIX_STACK_SIZE) fprintf(stderr, "RLGL: Matrix stack overflow\n"); // NO return — the bug

    State.stack[State.stackCounter] = *State.currentMatrix;
    State.stackCounter++;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    Matrix m; for (float *p=(float*)&m, *e=p+16; p<e; p++) *p = 7.0f; // recognizable payload
    State.currentMatrix = &m;
    State.stackCounter = 0;
    State.currentTextureId = 0xABCD1234;  // canary

    // 32 valid pushes fill stack[0..31]
    for (int i = 0; i < RL_MAX_MATRIX_STACK_SIZE; i++) rlPushMatrix();
    assert(State.stackCounter == 32);
    printf("after 32 pushes: stackCounter=%d, currentTextureId=0x%X (intact)\n",
           State.stackCounter, State.currentTextureId);

    // 33rd push: writes stack[32] == &stackCounter -> clobbers stackCounter + currentTextureId
    rlPushMatrix();
    printf("after 33rd push: stackCounter=%d (expected 33 if safe), currentTextureId=0x%X\n",
           State.stackCounter, State.currentTextureId);

    // Evidence of corruption: the neighbouring members were overwritten by Matrix bytes.
    if (State.currentTextureId != 0xABCD1234)
        printf(">>> BUG: adjacent State member 'currentTextureId' corrupted by the OOB write (now 0x%X)\n",
               State.currentTextureId);
    assert(State.currentTextureId == 0xABCD1234); // FAILS before fix (canary clobbered)
    printf("no corruption (only reached after the fix)\n");
    return 0;
}
