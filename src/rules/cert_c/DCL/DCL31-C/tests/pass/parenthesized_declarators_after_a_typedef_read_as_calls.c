/*
 * Rule: DCL31-C
 * Status: PASS - Should NOT trigger DCL31-C violation
 */

/*
 * Reason: a declaration that begins with a typedef name and parenthesizes
 * its declarator, `conn_p (a) = get();`, parses as a call of `conn_p`, and
 * so does a function-pointer declaration with a typedef return type,
 * `lng (*fp)(int) = 0;`. A type is never called, so neither is a call of an
 * undeclared function, and the pointer they declare is declared where it
 * is called.
 */

typedef long lng;
typedef struct conn *conn_p;
conn_p get(void);

int run(void)
{
    lng (*fp)(int) = 0;
    conn_p (a), (b) = get();
    conn_p (c);

    return fp(1) + (a == b) + (c == 0);
}
