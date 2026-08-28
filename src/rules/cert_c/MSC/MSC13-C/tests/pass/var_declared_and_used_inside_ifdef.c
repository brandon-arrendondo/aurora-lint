/*
 * Rule: MSC13-C
 * Source: hostap hostapd/ctrl_iface.c (task 386 follow-up regression,
 *         discovered benchmark-validating tasks 386/515, 2026-08-28)
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * A declaration written inside a #ifdef/#endif block is a direct child of
 * the preproc_ifdef node, one level away from any compound_statement --
 * find_enclosing_declaration_for_identifier's scope scan previously only
 * looked at a compound_statement's literal direct children, so it never
 * resolved ANY variable declared inside an #ifdef, making every use look
 * unresolvable and every such variable look "never read/used" -- an entire
 * function's worth of locals could be false-flagged this way whenever its
 * body was itself guarded by an #ifdef (the common #ifdef NEED_AP_MLME
 * idiom in hostap).
 */

#ifdef CONFIG_IEEE80211AX
static int f(int x) {
#ifdef NEED_AP_MLME
  int ret, color;
  unsigned int i;

  color = x;
  if (color == 0) {
    for (i = 0; i < 10; i++)
      g(i);
    return 0;
  }
  ret = color;
  return ret;
#else
  return 0;
#endif
}
#endif
