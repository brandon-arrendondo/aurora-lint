/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

volatile int *p;
/* ... */
(void) *(p++);