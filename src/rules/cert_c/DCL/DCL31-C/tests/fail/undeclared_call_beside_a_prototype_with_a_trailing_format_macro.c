/*
 * Rule: DCL31-C
 * Source: custom
 * Status: FAIL - recovering prototypes from around a function-like format
 * macro trailing a parameter list must not hide a call that nothing
 * declares.
 *
 * error_set and error_set_const are declared; error_reset is not, and is
 * still reported, and nothing else is.
 *
 * Expect: count=1
 */

typedef struct error_state error_state;

LIB_EXPORT
void error_set(error_state *error, const char *name, const char *format,
               ...) LIB_PRINTF_LIKE (3, 4);
LIB_EXPORT
void error_set_const(error_state *error, const char *name,
                     const char *message);

void report(error_state *error)
{
    error_set(error, "e.fail", "%s", "failed");
    error_set_const(error, "e.fail", "failed");
    error_reset(error); /* Expect: here */
}
