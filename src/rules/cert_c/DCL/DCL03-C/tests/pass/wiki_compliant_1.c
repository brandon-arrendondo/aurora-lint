/*
 * Rule: DCL03-C
 * Source: wiki
 * Status: PASS - Should NOT trigger DCL03-C violation
 */

struct timer {
  unsigned char MODE;
  unsigned int DATA;
  unsigned int COUNT;
};

#if (sizeof(struct timer) != (sizeof(unsigned char) + sizeof(unsigned int) + sizeof(unsigned int)))
  #error "Structure must not have any padding"
#endif
