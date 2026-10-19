/*
 * Rule: EXP47-C
 * Source: synthetic
 * Status: PASS - the call is to a different function, not va_arg
 * Description: A combining mark continues an identifier (C11 Annex D), so
 *   `x́va_arg` in the macro body is one name that ends in va_arg, not a
 *   va_arg call. The mark is two bytes long, and the start of the name must
 *   not be taken one byte after it.
 */

#include <stdarg.h>

int x́va_arg(va_list ap, unsigned short s);

#define NEXT_SHORT(ap) \
    x́va_arg(ap, unsigned short)
