/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: neither argument has a side effect. The first macro's body holds
 * a "//" inside a string literal, which starts no comment; the second
 * macro's body really does end on an open call. Reading either body must
 * not stop the scan.
 */

void show(const char *base, const char *what);
int f(int a, int b);

#define PORT 80
#define SHOW(p) show("http://example.org", #p)
#define OPEN(x) f(

void show_port(int n)
{
    SHOW(PORT);
    SHOW(n);
}

int open_call(int n)
{
    return OPEN(n) n, 1);
}
