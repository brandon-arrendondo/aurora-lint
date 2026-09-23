/*
 * Rule: INT31-C
 * Source: real-world (a follow-on fix)
 * Status: FAIL - Should trigger INT31-C violation
 */

/*
 * Reason: an earlier fix's fix for float-to-narrow-integer narrowing exact-matched
 * the spellings `float`/`double`/`long double` in get_type_width, so a
 * typedef'd floating type still fell through unrecognized. An earlier fix wires
 * get_type_width through the shared resolve_typedef_chain, so
 * `typedef double real_t; int r = real_var;` now resolves `real_t` -> `double`
 * -> the same FLOAT_AS_INTEGER_WIDTH row an unaliased spelling would land on
 * and the assignment is correctly flagged as narrowing.
 */

typedef double real_t;

void narrow_typedef_double(real_t measurement)
{
    int rounded = measurement;
    (void)rounded;
}
