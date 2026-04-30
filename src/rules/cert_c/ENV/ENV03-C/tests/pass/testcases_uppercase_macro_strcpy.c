/*
 * Rule: ENV03-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ENV03-C violation
 *
 * Tests: strcpy/strcat with ALL_CAPS macro constants as the source operand.
 * These are compile-time string constants, not tainted external input.
 * Juliet CWE-426 goodG2B pattern: strcpy(data, GOOD_OS_COMMAND)
 * where GOOD_OS_COMMAND expands to a full-path string literal.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SAFE_CMD "/usr/bin/ls"
#define SAFE_CMD_ARGS " -la"
#define FIXED_PATH "/bin/sh"

/* Uppercase macro as strcpy source — safe compile-time constant */
void test_strcpy_uppercase_macro(void) {
    char buf[256] = "";
    char *data = buf;
    strcpy(data, SAFE_CMD);
    FILE *pipe = popen(data, "r");
    if (pipe) pclose(pipe);
}

/* Uppercase macro as strcat source — safe compile-time constant */
void test_strcat_uppercase_macro(void) {
    char buf[256] = "/usr/bin/";
    char *data = buf;
    strcat(data, "ls");
    strcat(data, SAFE_CMD_ARGS);
    FILE *pipe = popen(data, "r");
    if (pipe) pclose(pipe);
}

/* Mixed: array initialized with uppercase macro, then used */
void test_array_init_uppercase_macro(void) {
    char buf[256];
    strcpy(buf, FIXED_PATH);
    FILE *pipe = popen(buf, "r");
    if (pipe) pclose(pipe);
}
