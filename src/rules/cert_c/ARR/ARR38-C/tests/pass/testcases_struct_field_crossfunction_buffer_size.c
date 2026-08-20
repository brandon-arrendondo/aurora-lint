// sqc-test: prescan
/*
 * Rule: ARR38-C
 * Source: Juliet flow variant 67 ("struct passed in a struct from one
 *   function to another, often in different source files"), task 304
 * Status: PASS - Should NOT trigger ARR38-C violation
 *
 * The sink's own body only sees `data = myStruct.structFirst;` -- it has
 * no idea the caller set structFirst to a 100-element buffer. Without
 * task 304's cross-function struct-field buffer-size tracking, this would
 * be flagged as a false positive (dest buffer size unknown, hardcoded
 * copy size looks suspicious).
 */

typedef struct { int *structFirst; } myStructType;

static void goodSink(myStructType myStruct)
{
    int *data = myStruct.structFirst;
    int source[100] = {0};
    memcpy(data, source, 100 * sizeof(int));
}

void caller(void)
{
    int dataGoodBuffer[100];
    myStructType myStruct;
    myStruct.structFirst = dataGoodBuffer;
    goodSink(myStruct);
}
