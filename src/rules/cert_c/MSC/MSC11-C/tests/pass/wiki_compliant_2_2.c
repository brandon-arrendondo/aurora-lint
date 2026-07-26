/*
 * Rule: MSC11-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

if (size > SIZE_MAX / sizeof(char *)) {
  fprintf(log_file, "%s: size %zu exceeds %zu bytes\n",
          __FILE__, size, SIZE_MAX / sizeof(char *));
  size = SIZE_MAX / sizeof(char *);
}
table_size = size * sizeof(char *);