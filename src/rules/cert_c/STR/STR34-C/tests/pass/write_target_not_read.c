/*
 * Rule: STR34-C
 * Source: task 574 (delta-adjudication of task 548, real-world FPs in curl/hostap)
 * Status: PASS - writing a constant through a char pointer is not a read,
 *   so it can't sign-extend; STR34-C should not fire on the assignment target.
 */

void nul_terminate(char *buf) {
    *buf = '\0';
}

void write_constant(char *p) {
    *p = 0;
}
