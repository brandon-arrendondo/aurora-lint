/*
 * Rule: MSC30-C
 * Status: PASS - `rand` here is a local function pointer, not the library
 *         function. Its declarations have a typedef return type, which the
 *         parser reads as a call (`INT(*rand)` called with `(void)`): the
 *         initializer, the keyword parameter and the file's own typedef each
 *         say it is a declaration.
 */

typedef int INT;
typedef unsigned SEED;

int next_value(void);

int initialized(void)
{
    INT (*rand)(SEED) = 0;
    rand = (INT (*)(SEED))next_value;
    return rand(1);  /* Compliant: the local */
}

int keyword_parameter(void)
{
    UNKNOWN_T (*rand)(void);
    rand = (int (*)(void))next_value;
    return rand();  /* Compliant: the local */
}

int file_typedef(void)
{
    INT (*rand)(SEED);
    rand = (INT (*)(SEED))next_value;
    return rand(2);  /* Compliant: the local */
}
