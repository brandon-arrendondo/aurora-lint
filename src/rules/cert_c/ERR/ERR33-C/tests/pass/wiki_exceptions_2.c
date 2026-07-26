/*
 * Rule: ERR33-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

int main() {
  (void) fprintf(stdout, "Hello, world\n"); // fprintf() return value safely ignored
}