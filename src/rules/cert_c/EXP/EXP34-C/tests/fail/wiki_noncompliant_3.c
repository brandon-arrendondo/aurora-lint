/*
 * Rule: EXP34-C
 * Source: wiki (adapted — use malloc for detectability without call-site data)
 * CERT's example as written is expected_fail/wiki_noncompliant_3_verbatim.c.
 * Status: FAIL - Should trigger EXP34-C violation
 */

#include <stdlib.h>

struct tun_struct {
  int sk;
  int reg_state;
};

void tun_chr_poll(void) {
  struct tun_struct *tun = (struct tun_struct *)malloc(sizeof(struct tun_struct));
  /* Use before NULL check — classic EXP34-C violation */
  int sk = tun->sk;

  if (!tun)
    return;

  (void)sk;
}
