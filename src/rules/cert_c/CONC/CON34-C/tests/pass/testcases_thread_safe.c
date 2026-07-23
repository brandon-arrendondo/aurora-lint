/*
 * Rule: CON34-C
 * Source: testcases
 * Status: PASS - Thread-safe alternatives
 */

#include <time.h>
#include <string.h>

/* localtime_r is thread-safe */
void use_localtime_r(void) {
    time_t t = time(NULL);
    struct tm result;
    localtime_r(&t, &result);
    (void)result;
}

/* strtok_r is thread-safe */
void use_strtok_r(char *str) {
    char *saveptr;
    char *tok = strtok_r(str, ",", &saveptr);
    (void)tok;
}
