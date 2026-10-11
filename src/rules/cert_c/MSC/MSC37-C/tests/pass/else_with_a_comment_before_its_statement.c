/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
 * Status: PASS - a comment after else is not the else's statement
 */

extern void *grab(void *p, unsigned long n);

void *first_try(void *p, unsigned long n, int fast) {
  if (fast)
    return 0; /* fail */
  else /* normal allocation */
    return grab(p, n);
}
