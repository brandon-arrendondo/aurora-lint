/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: FAIL - a forward goto skips the macro's return, so the macro does not return on
 * every path and the break after it is reachable
 */

extern int flag;
extern void f(void);

#define A() do { goto skip; return -1; skip: ; } while (0)
#define B() do { if (flag) goto skip; return -1; skip: f(); } while (0)
#define C() do { goto in; return -1; for (;;) { in: break; } } while (0)

int g0(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        A();
        break;
    }
}

int g1(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        B();
        break;
    }
}

int g2(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        C();
        break;
    }
}
