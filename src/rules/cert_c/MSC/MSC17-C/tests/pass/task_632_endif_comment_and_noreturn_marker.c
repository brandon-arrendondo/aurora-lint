/*
 * Rule: MSC17-C
 * Source: hostap src/ap/ieee802_11.c + src/common/wpa_common.c,
 *         pure-ftpd src/pure-pw.c (task 632)
 * Status: PASS - Should NOT trigger MSC17-C violation
 *
 * Three distinct fixes exercised together:
 *  - an empty grouped case label spread across an #ifdef must not pick up
 *    the closing #endif's own name-annotation comment as if it were case
 *    content;
 *  - a genuine "fall through" comment placed *inside* an #ifdef branch must
 *    not be shadowed by that branch's trailing #endif comment once control
 *    returns to the enclosing switch body;
 *  - a marker comment (fall-through or "doesn't return") sitting just
 *    inside a brace-wrapped case body must still be found.
 */

enum { A, B, C, D, E };

void f(int key_mgmt, int op) {
  switch (key_mgmt) {
#ifdef CONFIG_SAE
  case A:
  /* fall through */
#endif /* CONFIG_SAE */
#ifdef CONFIG_SOMETHING
  case B:
#endif /* CONFIG_SOMETHING */
#ifdef CONFIG_OTHER
  case C:
    do_thing();
    return;
#endif /* CONFIG_OTHER */
  default:
    break;
  }

  switch (op) {
  case D: {
    help();
    /* doesn't return */
  }
  case E:
    do_other();
    break;
  }
}
