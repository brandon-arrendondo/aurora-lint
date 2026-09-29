/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: CAST(T, x) expands to (T)(x), a cast when T names a type. The
 * primitive type, the file's typedef and the standard _t name all make it a
 * cast, which evaluates nothing, so every use is pure under both presets.
 */

#include <stdint.h>

#define CAST(T, x) (T)(x)
#define TO_U32(x) (uint32_t)(x)
#define TWICE(x) ((x) + (x))

typedef unsigned long word;

long a(long v) {
    return TWICE(CAST(long, v));
}

word b(word v) {
    return TWICE(CAST(word, v));
}

uint32_t c(uint32_t v) {
    return TWICE(TO_U32(v));
}
