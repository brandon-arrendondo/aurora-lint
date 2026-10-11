/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and maintainer ruling, rulings walk-through Q9
 * Status: PASS - a function returning a typedef of void returns no value
 */

typedef void VOID;

VOID reset(int *p) {
  *p = 0;
}
