/*
 * Rule: STR30-C
 * Source: custom
 * Status: FAIL - Should trigger STR30-C violation
 * Description: g passes its parameter to itself and writes through a copy
 * of what that call returns, reached through four more alias links. Whether
 * g writes through its parameter depends on whether g returns it, which is
 * still being worked out, and reads "no" meanwhile, when an alias's answer
 * is first asked. That provisional answer must not be remembered for the
 * next write: main's call writes into the literal through g.
 */

char *g(char *p) {
    char loc[8];
    char *x = g(loc);
    char *t = g(p + 1);
    char *u = t;
    char *a1 = u;
    char *a2 = a1;
    char *a3 = a2;
    char *a4 = a3;
    x[0] = 0;
    a4[0] = 'x';
    if (*p) return u;
    return p;
}
int main(void) { g("lit"); return 0; }
