/*
 * Rule: ARR30-C
 * Source: task 1000 (sqlite vdbe.c:314 real-world FP)
 * Status: PASS - Should NOT trigger ARR30-C violation
 *
 * &pCx->aType[nField] computes the ADDRESS of the nField-th element -- a
 * valid pointer even when nField equals the array's element count (C99
 * 6.5.6p8, one-past-the-end). It is never dereferenced here, so this is not
 * an array READ and the unvalidated-parameter-index check must not fire on
 * it.
 */

typedef struct Cursor {
  int nField;
  unsigned char *aOffset;
  unsigned char aType[1];
} Cursor;

void set_offset(Cursor *pCx, int nField) {
  pCx->nField = nField;
  pCx->aOffset = &pCx->aType[nField];
}
