// sqc-test: prescan
/*
 * Rule: ARR38-C
 * Source: Juliet flow variant 67 ("struct passed in a struct from one
 *   function to another, often in different source files"), task 304
 * Status: FAIL - Should trigger ARR38-C violation
 *
 * Mirrors testcases_struct_field_crossfunction_buffer_size.c's PASS case,
 * but the caller's buffer (50 elements) is smaller than the sink's
 * hardcoded copy (100 elements) -- the genuine overflow this rule exists
 * to catch must still fire even though the destination is resolved
 * through a struct-by-value parameter's field.
 */

typedef struct { int *structFirst; } myStructType;

static void badSink(myStructType myStruct)
{
    int *data = myStruct.structFirst;
    int source[100] = {0};
    memcpy(data, source, 100 * sizeof(int));
}

void caller(void)
{
    int dataBadBuffer[50];
    myStructType myStruct;
    myStruct.structFirst = dataBadBuffer;
    badSink(myStruct);
}
