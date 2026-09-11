/*
 * Rule: DCL06-C
 * Source: bmdb-757
 * Status: FAIL - Noncompliant, must not be over-suppressed
 * Description: a comparison against a plain variable (not a version macro)
 * must still be flagged, guarding against the DCL06-C-757 version-macro
 * exemption over-firing on ordinary threshold comparisons.
 */

int check_threshold(int count) {
    if (count > 47) {
        return 1;
    }
    return 0;
}
