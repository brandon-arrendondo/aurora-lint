/*
 * Rule: MSC13-C
 * Source: real-world/1193 (fail-twin guard: fixing the parse for the
 *   comment-before-else-if dangling-else shape must not also stop a
 *   genuine dead store from being caught once the chain parses cleanly)
 * Status: FAIL - Should trigger MSC13-C violation
 *
 * `result` is set on the first arm but unconditionally overwritten right
 * after the whole chain, before its only read -- a real dead store, not
 * the guard idiom the companion pass fixture exists to exempt.
 */
int f(int lib, int reason) {
    int result;
    if ((lib == 1) && (reason == 1)) {
        result = 10;
    }
#ifdef SOME_GUARD
    /* comment explaining the guard */
    else if ((lib == 1) && (reason == 2)) {
        result = 20;
    }
#endif
    else {
        result = 30;
    }
    result = 99;
    return result;
}
