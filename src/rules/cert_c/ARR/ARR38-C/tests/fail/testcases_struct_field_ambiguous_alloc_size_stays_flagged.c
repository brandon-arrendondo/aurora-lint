/*
 * Rule: ARR38-C
 * Source: CWE-131 "Incorrect Calculation of Buffer Size" combined with
 *   Juliet flow variant 67 (struct-by-value cross-function field), task 304
 * Status: FAIL - Should trigger ARR38-C violation
 *
 * `ALLOCA(10)` cast to `int *` allocates 10 BYTES, not 10 ints -- a bare
 * byte count with no `sizeof` is ambiguous for a struct field's
 * arbitrary-typed pointee, and must NOT be trusted as "10 elements" the
 * way an explicit `10*sizeof(int)` would be. Even in the "good-looking"
 * caller (which the analogous unambiguous case would suppress), this
 * must stay conservatively flagged rather than risk proving a genuinely
 * undersized buffer "safe".
 */

typedef struct { int *structFirst; } myStructType;

static void goodLookingSink(myStructType myStruct)
{
    int *data = myStruct.structFirst;
    int source[10] = {0};
    memcpy(data, source, 10 * sizeof(int));
}

void caller(void)
{
    /* FLAW: allocates 10 bytes, not 10 ints -- ambiguous byte count. */
    int *data = (int *) ALLOCA(10);
    myStructType myStruct;
    myStruct.structFirst = data;
    goodLookingSink(myStruct);
}
