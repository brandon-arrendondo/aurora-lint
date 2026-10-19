/*
 * Rule: FIO21-C
 * Source: regression
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 * Settings: posix_version=2008
 *
 * POSIX is declared, and POSIX removes the file tmpfile() creates, so the
 * default policy does not report the call (fio21_tmpfile_exempt_under_posix).
 * The strict policy reports it whatever the environment, as CERT's page is
 * written.
 */

#include <stdio.h>

FILE *scratch(void) {
    return tmpfile();
}
