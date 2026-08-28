/*
 * Rule: STR31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger STR31-C violation
 * Reason: malloc(sizeof(struct big_record)) resolves to the type's byte
 * size (task 515: bare sizeof(T) allocation size); the short copy fits.
 */

#include <stdlib.h>
#include <string.h>

struct big_record {
    char data[256];
};

int main() {
    char *dest = malloc(sizeof(struct big_record));

    if (dest) {
        strcpy(dest, "short");
        free(dest);
    }

    return 0;
}
