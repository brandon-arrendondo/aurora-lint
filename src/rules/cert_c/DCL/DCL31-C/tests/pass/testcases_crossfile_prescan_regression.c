/*
 * Rule: DCL31-C
 * Source: testcases
 * Status: PASS - Functions found by prescan should not be flagged as undeclared
 * Regression: Round 6 fix — cross-file function definitions suppress false positives
 *
 * Without prescan context, helper_compute() and process_buffer() would be
 * flagged because they are called before their definitions appear in the file.
 * The prescan marker causes the test harness to build intra-file prescan
 * context, simulating the -d flag that discovers functions across files.
 */

void caller_function(void) {
    /* These calls appear before the function definitions below.
     * DCL31-C's sequential traversal would flag them as undeclared,
     * but prescan discovers them and populates cross_file_functions. */
    int result = helper_compute(42);
    process_buffer("hello", 5);
    (void)result;
}

int helper_compute(int value) {
    return value * 2;
}

void process_buffer(const char *buf, int len) {
    (void)buf;
    (void)len;
}
