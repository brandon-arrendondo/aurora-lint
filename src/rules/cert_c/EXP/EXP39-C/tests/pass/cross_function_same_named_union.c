/*
 * Rule: EXP39-C
 * Source: regression (cross-function scoping bug)
 * Status: PASS - Should NOT trigger EXP39-C violation
 *
 * Two different functions each declare their own local `union event`
 * variable named `event` and access its members. Reading or writing a
 * union member is an access through that member's own type, so neither
 * function accesses an object through an incompatible type, and a local
 * in one function says nothing about a same-named local in another.
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
