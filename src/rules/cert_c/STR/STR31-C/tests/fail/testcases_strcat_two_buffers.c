/*
 * Rule: STR31-C
 * Description: Two buffers each overflowed by successive strcat calls; the one appended to first is reported
 * Status: FAIL - Should trigger STR31-C violation
 */

#include <string.h>

void build_paths(void) {
    const char *head_part = "abcd";
    const char *tail_part = "efgh";
    char second[8] = "";
    char first[8] = "";
    strcat(first, head_part);
    strcat(second, head_part);
    strcat(first, tail_part);
    strcat(second, tail_part);
}
