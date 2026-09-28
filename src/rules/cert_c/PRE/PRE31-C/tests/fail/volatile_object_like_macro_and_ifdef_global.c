/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: STATUS expands to a volatile read, and flag is a file-scope
 * volatile object declared under #ifdef, so read_status() and peek() both
 * read a volatile object: a side effect under both presets.
 */

#define STATUS (*(volatile unsigned *)0x40000000u)
#define TWICE(x) ((x) + (x))

#ifdef CONFIG_FLAG
static volatile int flag;
#endif

static unsigned read_status(void) {
    return STATUS;
}

static int peek(void) {
    return flag;
}

unsigned use_status(void) {
    return TWICE(read_status());
}

int use_flag(void) {
    return TWICE(peek());
}

unsigned direct_status(void) {
    return TWICE(STATUS);
}
