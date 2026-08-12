/*
 * Rule: MSC13-C
 * Status: FAIL - a genuine dead store inside a `#if`/`#endif`-guarded case
 * arm must still be caught (task 445): resolving the preprocessor split
 * must not blind the CFG to real violations within the visited arm.
 */

#define SUPPORT_FILEFORMAT_WAV 1

void f(int ctxType)
{
    switch (ctxType)
    {
    #if SUPPORT_FILEFORMAT_WAV
        case 1:
        {
            int unused = 5;   /* VIOLATION: dead store — never read */
            unused = 6;
        } break;
    #endif
        default:
            break;
    }
}
