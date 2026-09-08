/*
 * Rule: EXP33-C
 * Source: task 1065 (hostap wpa_supplicant/eapol_test.c:1042/1044 recall regression)
 * Status: FAIL - Should trigger EXP33-C violation
 */

/*
 * Reason: sscanf's return is the count of successfully matched fields.
 * When the return is discarded (bare expression_statement), a partial
 * match leaves some of the variadic outputs uninitialized. Task 1029
 * over-corrected by unconditionally crediting every scanf variadic
 * output as initialized regardless of return, so the exact hostap shape
 * below was silently missed (task 1065). The fix (init_state.rs) skips
 * the credit for scanf-family calls whose return is discarded, so the
 * subsequent value-reads of `a[0..3]` correctly trigger EXP33-C.
 *
 * Real reproducer: hostap wpa_supplicant/eapol_test.c:1042 --
 *   int a[4];
 *   sscanf(authsrv, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]);
 *   *pos++ = a[0]; *pos++ = a[1]; *pos++ = a[2]; *pos++ = a[3];
 * -- flagged before task 1029, silently missed after, restored here.
 */

extern int sscanf(const char *s, const char *fmt, ...);

int parse_ip(const char *authsrv)
{
    int a[4];
    sscanf(authsrv, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]);
    return a[0] + a[1] + a[2] + a[3];
}
