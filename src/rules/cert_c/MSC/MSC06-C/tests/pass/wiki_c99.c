/*
 * Rule: MSC06-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

/* memset_s.c */
errno_t memset_s(void *v, rsize_t smax, int c, rsize_t n) {
  if (v == NULL) return EINVAL;
  if (smax > RSIZE_MAX) return EINVAL;
  if (n > smax) return EINVAL;

  volatile unsigned char *p = v;
  while (smax-- && n--) {
    *p++ = c;
  }

  return 0;
}

/* getPassword.c */
extern errno_t memset_s(void *v, rsize_t smax, int c, rsize_t n);

void getPassword(void) {
  char pwd[64];

  if (retrievePassword(pwd, sizeof(pwd))) {
     /* Checking of password, secure operations, etc. */
  }
  if (memset_s(pwd, sizeof(pwd), 0, sizeof(pwd)) != 0) {
    /* Handle error */
  }
}