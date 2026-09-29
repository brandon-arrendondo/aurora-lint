/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * This sqlite3_mprintf hands its format to vsnprintf(), whose `%s` reads
 * the string. Its name is not what decides whether a NULL argument is
 * tolerated: the body that gets linked does. So a possibly-null getenv()
 * result reaching the `%s` conversion is reported, as it would be for any
 * other formatter.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

char *sqlite3_mprintf(const char *zFormat, ...) {
    static char buf[256];
    va_list ap;
    va_start(ap, zFormat);
    vsnprintf(buf, sizeof buf, zFormat, ap);
    va_end(ap);
    return buf;
}

char *home_path(void) {
    char *home = getenv("HOME");
    return sqlite3_mprintf("%s/.sqliterc", home);
}
