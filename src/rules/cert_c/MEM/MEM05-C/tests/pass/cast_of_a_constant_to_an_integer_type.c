/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: PASS - A cast of a constant to an integer type is a constant
 *
 * A cast in an integer constant expression converts an arithmetic type to
 * an integer type (C11 6.6p6), and a floating constant may be its
 * immediate operand. A cast to a builtin integer type, to an integer
 * typedef and to an enumerated type each keeps the size constant.
 */
typedef unsigned short count_t;
enum width { narrow = 4, wide = 8 };

void sink(char *p);

void fixed_sizes(void)
{
    char by_builtin[(unsigned char)260];
    char by_float_literal[(int)2.5];
    char by_typedef[(count_t)12];
    char by_enum[(enum width)8];
    sink(by_builtin);
    sink(by_float_literal);
    sink(by_typedef);
    sink(by_enum);
}
