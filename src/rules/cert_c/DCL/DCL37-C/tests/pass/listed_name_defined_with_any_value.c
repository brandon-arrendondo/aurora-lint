/*
 * Rule: DCL37-C
 * Status: PASS - the exemption is for the name: defining a listed feature-test
 * macro is not reported whatever its value, which is not checked.
 */

#define _POSIX_C_SOURCE garbage

int main(void) { return 0; }
