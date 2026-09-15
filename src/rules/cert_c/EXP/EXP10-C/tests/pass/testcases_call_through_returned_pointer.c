/*
 * Rule: EXP10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP10-C violation
 * Description: A call whose function designator is itself computed by
 * calls, with no side-effecting argument, has nothing unsequenced: the
 * designator is fully evaluated, then the arguments, then the body.
 * curl's (UI_method_get_writer(UI_OpenSSL()))(ui, uis) and sqlite's
 * ORIGVFS(pVfs)->xDlOpen(ORIGVFS(pVfs), zPath).
 */

typedef int (*writer_fn)(void *ui, void *uis);
extern void *ui_openssl(void);
extern writer_fn method_get_writer(void *m);

int f(void *ui, void *uis) {
  return (method_get_writer(ui_openssl()))(ui, uis);
}
