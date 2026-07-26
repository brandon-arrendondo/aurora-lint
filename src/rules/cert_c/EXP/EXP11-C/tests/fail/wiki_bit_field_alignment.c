/*
 * Rule: EXP11-C
 * Source: wiki
 * Status: FAIL - Should trigger EXP11-C violation
 */

struct bf {
  unsigned int m1 : 8;
  unsigned int m2 : 8;
  unsigned int m3 : 8;
  unsigned int m4 : 8;
}; /* 32 bits total */

void function() {
  struct bf data;
  unsigned char *ptr;

  data.m1 = 0;
  data.m2 = 0;
  data.m3 = 0;
  data.m4 = 0;
  ptr = (unsigned char *)&data;
  (*ptr)++; /* Can increment data.m1 or data.m4 */
}