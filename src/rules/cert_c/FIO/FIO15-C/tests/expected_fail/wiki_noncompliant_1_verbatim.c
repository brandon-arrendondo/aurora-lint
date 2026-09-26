/*
 * Rule: FIO15-C
 * Source: wiki, CERT FIO15-C "Noncompliant Code Example", verbatim
 * Status: EXPECTED_FAIL - CERT's own noncompliant example, not detected yet
 *
 * CERT's noncompliant example as written: a file named by a variable is
 * created and later removed without the directory being known to be secure.
 */

char *file_name;
FILE *fp;

/* Initialize file_name */

fp = fopen(file_name, "w");
if (fp == NULL) {
  /* Handle error */
}

/* ... Process file ... */

if (fclose(fp) != 0) {
  /* Handle error */
}

if (remove(file_name) != 0) {
  /* Handle error */
}
