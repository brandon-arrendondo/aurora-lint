/*
 * Rule: DCL31-C
 * Source: custom
 * Status: PASS - Should NOT trigger DCL31-C violation
 * Description: Each prototype opens with an export macro on a line of its
 * own, and the variadic one ends in a function-like format macro after its
 * parameter list, the way a library header declares its printf-like API.
 * Every function called below is declared, the one after the format macro
 * included.
 */

typedef struct error_state error_state;

LIB_EXPORT
void error_free(error_state *error);
LIB_EXPORT
void error_set(error_state *error, const char *name, const char *format,
               ...) LIB_PRINTF_LIKE (3, 4);
LIB_EXPORT
void error_set_const(error_state *error, const char *name,
                     const char *message);
LIB_EXPORT
void error_move(error_state *src, error_state *dest);

void report(error_state *error, error_state *saved)
{
    error_set(error, "e.fail", "%s", "failed");
    error_set_const(error, "e.fail", "failed");
    error_move(error, saved);
    error_free(error);
}
