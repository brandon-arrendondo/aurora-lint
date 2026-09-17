/*
 * Rule: MSC13-C
 * Source: task 1151/1193 (fail-twin guard: fixing the parse for the
 *   trailing-else-after-a-complete-guarded-if shape must not also stop a
 *   genuine dead store from being caught once the chain parses cleanly)
 * Status: FAIL - Should trigger MSC13-C violation
 *
 * `result` is set in the else branch but unconditionally overwritten
 * right after, before its only read -- a real dead store, not the guard
 * idiom the companion pass fixture exists to exempt.
 */
int f(int detail) {
    int result;
    if (detail == 1) {
        return -1;
    }
#ifdef SOME_GUARD
    if (detail == 2) {
        return -1;
    }
#endif
    else {
        result = 3;
    }
    result = 99;
    return result;
}
