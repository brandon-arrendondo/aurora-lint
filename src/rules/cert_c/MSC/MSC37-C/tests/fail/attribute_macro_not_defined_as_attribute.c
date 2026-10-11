/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: FAIL under every preset
 *
 * `NORETURN` is defined as nothing here, so it declares nothing: a macro
 * credits a function only by what it expands to.
 */

#define NORETURN

void halt(void) NORETURN;

int parse(int token)
{
    if (token > 0) {
        return token;
    }
    halt();
}
