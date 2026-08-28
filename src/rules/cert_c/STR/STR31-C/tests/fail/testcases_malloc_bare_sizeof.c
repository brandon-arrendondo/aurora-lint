/*
 * Rule: STR31-C
 * Source: testcases
 * Status: FAIL - Should trigger STR31-C violation
 * Reason: malloc(sizeof(char)) allocates exactly 1 byte; the string literal
 * copied in needs far more space (task 515: bare sizeof(T) allocation size).
 */

#include <stdlib.h>
#include <string.h>

int main() {
    char *dest = malloc(sizeof(char));

    if (dest) {
        strcpy(dest, "too long for one byte");
        free(dest);
    }

    return 0;
}
