/*
 * Rule: FIO10-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO10-C violation. A bare return-value
 * check is NOT sufficient on its own, even on POSIX: rename() silently
 * replaces an existing destination there, which is itself noncompliant
 * if the intent was to preserve it, and error checking alone only
 * detects the problem after it occurs (verified against live CERT
 * wiki). Previously mislabeled PASS on the mistaken premise that POSIX's
 * atomic-replace semantics made return-value checking sufficient.
 */

#include <stdio.h>

void posix_rename_with_error_check(const char *src, const char *dst) {
    if (rename(src, dst) != 0) {
        perror("rename failed");
    }
}

void posix_rename_negated_check(const char *src, const char *dst) {
    if (!rename(src, dst)) {
        /* success */
    }
}
