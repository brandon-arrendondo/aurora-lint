/*
 * Rule: ARR30-C
 * Source: custom
 * Status: FAIL - Should trigger ARR30-C violation
 * Description: An #if between the entries of a local array's initializer
 * list. The grammar has no production for a conditional inside an
 * initializer list, so unrepaired the #if swallowed the rest of the body and
 * the declaration of `tbl` was lost; its size was unknown and the read one
 * past the end went unreported. The conditional's entries rejoin the list,
 * and the declaration is read whole.
 * Expect: count=1
 */

int last_entry(void)
{
    int tbl[2] = {
#if defined(WITH_EXTRA_ENTRY)
        1,
#endif
        0
    };
    return tbl[2]; /* Expect: here */
}
