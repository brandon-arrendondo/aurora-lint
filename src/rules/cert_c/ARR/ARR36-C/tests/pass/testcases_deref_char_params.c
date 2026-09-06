/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: PASS
 * Reason: '*s1' over a single-level 'char *s1' is the pointed-to CHARACTER,
 *         not a pointer, so '*s1 - *s2' subtracts two values and names no
 *         array on either side. Distilled from hostap
 *         src/utils/os_internal.c: os_strcmp, os_strncmp and os_memcmp all
 *         end in this shape and all three were reported as pointer
 *         subtraction between 'param:s1' and 'param:s2'.
 */

#include <stddef.h>

int str_compare(const char *s1, const char *s2)
{
    while (*s1 == *s2) {
        if (*s1 == '\0') {
            return 0;
        }
        s1++;
        s2++;
    }

    /* Two characters, not two pointers. */
    return *s1 - *s2;
}

int mem_compare(const unsigned char *p1, const unsigned char *p2, size_t n)
{
    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    return 0;
}

int first_is_smaller(const int *a, const int *b)
{
    /* Two ints compared, through two pointer parameters. */
    return *a < *b;
}
