/*
 * Rule: INT13-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

fd = open(file_name, UO_WRONLY | UO_CREAT | UO_EXCL | UO_TRUNC, 0600);