/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation.
 * `pTrigger` is assigned in the `#ifndef GUARD` branch, but `#define`d to a
 * constant in the `#else` branch instead of being assigned -- aurora-lint has no
 * preprocessor, so a later, unconditional read looked like a join of
 * "assigned in one branch, untouched in the other" (MaybeUninitialized).
 * But in every actually-compiled configuration this is safe: whichever
 * branch's condition holds, `pTrigger` is either assigned directly, or
 * `#define`d to a constant the preprocessor substitutes at every later use
 * (including this read) for the rest of the translation unit -- so this
 * "read" is never actually of the variable in that configuration (task 461
 * category 5; sqlite's insert.c/delete.c/update.c pTrigger/tmask/isView).
 */
struct Trigger;
struct Trigger *triggers_exist(struct Trigger *pTab, int *tmaskOut);

void f(struct Trigger *pTab) {
    struct Trigger *pTrigger;
    int tmask;
#ifndef SQLITE_OMIT_TRIGGER
    pTrigger = triggers_exist(pTab, &tmask);
#else
# define pTrigger 0
# define tmask 0
#endif
    if (pTrigger && tmask) {
        /* ... */
    }
}
