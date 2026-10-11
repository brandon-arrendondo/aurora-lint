/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation
 *
 * `NORETURN` is a macro defined as the C11 `_Noreturn` specifier. The
 * parser never sees the keyword, so only the macro's definition says the
 * function is noreturn; the default preset resolves it
 * (`msc37_attribute_noreturn`), the others do not.
 */

#define NORETURN _Noreturn

void halt(void) NORETURN;

int parse(int token)
{
    if (token > 0) {
        return token;
    }
    halt();
}
