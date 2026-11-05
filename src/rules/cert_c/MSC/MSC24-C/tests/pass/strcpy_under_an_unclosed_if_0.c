/*
 * Rule: MSC24-C
 * Source: custom
 * Status: PASS - Should NOT trigger MSC24-C violation
 * Description: An `#if 0` no `#endif` closes keeps an old copy routine out
 * of the build. The unclosed conditional's directive is blanked so the file
 * parses, and the arm `#if 0` proves dead is blanked with it: the `strcpy`
 * there is not code any build compiles, and is not reported.
 */

#include <string.h>

void copy_name(char *dst, size_t size, const char *src)
{
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}

#if 0
void copy_name_unchecked(char *dst, const char *src)
{
    strcpy(dst, src);
}
