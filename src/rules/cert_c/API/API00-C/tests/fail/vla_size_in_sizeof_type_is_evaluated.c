/*
 * Rule: API00-C
 * Source: synthetic
 * Status: FAIL - Should trigger API00-C violation
 * Expect: count=1
 *
 * The operand of `sizeof` is evaluated when its type is a variable length
 * array (C11 6.5.3.4p2), so `n * 4` in `sizeof(char[n * 4])` is computed
 * from the unvalidated parameter, as it would be anywhere else.
 */
#include <stddef.h>

size_t scaled_size(size_t n) { return sizeof(char[n * 4]); }
