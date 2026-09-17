/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO47-C violation
 *
 * `char buf[N]` decays to a pointer wherever it's passed as a call
 * argument. process_declaration()'s is_pointer check only looked for a
 * literal '*' in the declaration text, so an array declarator (no '*' at
 * all) was miscategorized as the array's element type instead - here
 * Integer (from "char") rather than Pointer - producing a bogus "%s
 * expects Pointer but argument is Integer" mismatch.
 */
#include <stdio.h>

void log_date(void) {
    char date[32];
    snprintf(date, sizeof date, "%d", 2026);
    printf("Date: %s\n", date);
}

int main(void) {
    log_date();
    return 0;
}
