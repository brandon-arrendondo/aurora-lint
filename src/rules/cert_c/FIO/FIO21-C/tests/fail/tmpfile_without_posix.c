/*
 * Rule: FIO21-C
 * Source: regression
 * Status: FAIL - Should trigger FIO21-C violation
 * Settings: posix_version=none
 *
 * The project declares it is not built for POSIX, so no preset credits
 * POSIX's removal of the file tmpfile() creates, and the call is reported
 * under the default preset too.
 */

#include <stdio.h>

FILE *scratch(void) {
    return tmpfile();
}
