/*
 * Rule: STR31-C
 * Description: The buffer is sized by BUF_LEN; BUF, a shorter bound that is a prefix of its name, must not be read as its size
 * Status: PASS - Should NOT trigger STR31-C violation
 */

#include <string.h>

#define BUF 4
#define BUF_LEN 64

void copy_name(void) {
    char name[BUF_LEN];
    strcpy(name, "abcdefgh");
}
