/*
 * Rule: STR31-C
 * Description: The buffer is sized by BUF_LEN; BUF, a longer bound that is a prefix of its name, must not be read as its size
 * Status: FAIL - Should trigger STR31-C violation
 */

#include <string.h>

#define BUF 64
#define BUF_LEN 4

void copy_name(void) {
    char name[BUF_LEN];
    strcpy(name, "abcdefgh");
}
