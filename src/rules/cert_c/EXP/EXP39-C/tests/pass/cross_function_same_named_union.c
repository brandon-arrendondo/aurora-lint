/*
 * Rule: EXP39-C
 * Source: regression (cross-function scoping bug)
 * Status: PASS - Should NOT trigger EXP39-C violation
 *
 * Two different functions each declare their own local `union event`
 * variable named `event`. Each function only accesses a single member of
 * its own union, so there is no type punning within either function.
 * A prior bug aggregated union_member_accesses by variable name across the
 * whole translation unit, so accessing different members of two distinct,
 * same-named local unions in different functions looked like punning
 * within a single object. That must not fire here.
 */

union event {
  struct {
    int type;
    int code;
  } generic;
  struct {
    int type;
    int value;
  } assoc;
};

void handle_generic(void) {
  union event event;
  event.generic.type = 1;
  event.generic.code = 2;
}

void handle_assoc(void) {
  union event event;
  event.assoc.type = 1;
  event.assoc.value = 3;
}
