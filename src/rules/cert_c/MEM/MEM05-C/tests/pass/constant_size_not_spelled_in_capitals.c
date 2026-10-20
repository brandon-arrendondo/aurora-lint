/*
 * Rule: MEM05-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM05-C violation
 * Description: Each size is an integer constant expression (C23 6.6), so each
 * array is fixed-size, not a VLA: a lowercase object-like macro, one defined
 * to a constant in every #if arm, an enumerator, sizeof, a character
 * constant, suffixed and hexadecimal literals, and arithmetic over them;
 * sizeof of a fixed-size array type, of a header typedef, and of a local
 * typedef of a fixed-size array or an object of one. The
 * rule once took only digit strings and lone ALL_CAPS names for constants and
 * reported every one of these as a runtime-sized allocation.
 */
#include <stddef.h>

#define bufsize 64
#define MAXN 16
#ifdef BIG
#define armed 1024
#else
#define armed 64
#endif

enum { slots = 8 };
struct pair { int a; int b; };

void fixed_sizes(void) {
    char lowercase_macro[bufsize];
    char per_arm[armed];
    int by_enumerator[slots];
    char by_sizeof[sizeof(struct pair)];
    char by_sizeof_array[sizeof lowercase_macro];
    char by_char['z'];
    char suffixed[16u];
    char hex[0x10];
    char sum[MAXN + 1];
    char product[(2 * MAXN)];
    char cast[(size_t)slots];
    char by_array_type[sizeof(int[4])];
    char by_header_typedef[sizeof(size_t)];
    char by_alignment[_Alignof(int)];
    typedef int fixed_row[4];
    fixed_row row;
    char by_fixed_typedef[sizeof(fixed_row)];
    char by_fixed_typedef_object[sizeof row];
    (void)lowercase_macro; (void)per_arm; (void)by_enumerator; (void)by_sizeof;
    (void)by_sizeof_array; (void)by_char; (void)suffixed; (void)hex; (void)sum;
    (void)product; (void)cast; (void)by_array_type; (void)by_header_typedef;
    (void)by_alignment; (void)by_fixed_typedef; (void)by_fixed_typedef_object;
}
