/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC12-C violation
 */

int s_loop(char *s) {
    size_t i;
    size_t len = strlen(s);
    for (i=0; i < len; i++) {
        /* Code that doesn't change s, i, or len */
      if (s[i] == '\0') {
        /* This code is never reached */
      }
    }
    return 0;
}