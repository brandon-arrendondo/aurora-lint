/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * `NORETURN` is a macro defined as the C11 `_Noreturn` specifier. The
 * parser never sees the keyword, so only the macro's definition says the
 * function is noreturn. The standard keyword is credited through a macro as
 * it is written directly, wherever the keyword is trusted; the pedantic
 * preset trusts only a body verified never to return.
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
