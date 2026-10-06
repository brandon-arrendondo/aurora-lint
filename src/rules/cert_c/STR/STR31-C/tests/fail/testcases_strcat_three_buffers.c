/*
 * Rule: STR31-C
 * Description: Three buffers appended to in turn, two of them overflowed; the first overflowed buffer appended to is reported
 * Status: FAIL - Should trigger STR31-C violation
 */

#include <string.h>

void build_labels(void) {
    const char *stem = "abc";
    const char *suffix = "def";
    char roomy[64] = "";
    char tight[6] = "";
    char cramped[6] = "";
    strcat(roomy, stem);
    strcat(cramped, stem);
    strcat(tight, stem);
    strcat(roomy, suffix);
    strcat(tight, suffix);
    strcat(cramped, suffix);
}
