/*
 * Rule: MSC17-C
 * Source: pure-ftpd src/pure-ftpwho.c (task 632)
 * Status: FAIL - Should trigger MSC17-C violation
 *
 * A real, unmarked fallthrough must still be flagged even after the task
 * 632 fixes for comment-only grouped cases, #endif annotations, and
 * brace-wrapped markers -- those fixes must not blanket-suppress genuine
 * violations.
 */

void f(int c) {
  switch (c) {
  case 'C':
  case 'c':
    html_cgi++;
  case 'W':
    html_raw++;
    break;
  }
}
