/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: STEP is an object-like macro naming ext_step, a function no
 * scanned file defines, not a type, so `(STEP)(1)` calls it and nothing
 * proves the call pure. Neither is `(WORD)(2)` a cast: WORD is defined as
 * a type in one build only, and as a function's name in the other.
 */

int ext_step(int);
int ext_word(int);

#define STEP ext_step
#ifdef WIDE
#define WORD unsigned long
#else
#define WORD ext_word
#endif

#define TWICE(x) ((x) + (x))

int step(void) {
    return TWICE((STEP)(1));  // Expect: here
}

int word(void) {
    return TWICE((WORD)(2));  // Expect: here
}
