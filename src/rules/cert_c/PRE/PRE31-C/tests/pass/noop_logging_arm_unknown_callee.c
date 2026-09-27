/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: LOG drops its argument in one arm, but the argument's only
 * possible side effect is a call to a function no scanned file defines.
 * The default policy does not treat such a call as a side effect
 * (pre31_unknown_call_pure); the strict policy does.
 */

const char *describe(int state);

#ifdef DEBUG
#define LOG(s) (void)(s)
#else
#define LOG(s)
#endif

void l(int state) {
    LOG(describe(state));
}
