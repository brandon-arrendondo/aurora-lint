/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: FAIL - the default and the returns belong to a switch nested in the macro's switch, so
 * the macro's own switch can fall out without returning
 */

extern int flag;
extern void f(void);

#define A(x, y) switch (x) { default: return -1; case 1: switch (y) { case 2: return -2; } }
#define B(x, y) switch (x) { case 1: switch (y) { default: return -2; } }

int g0(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        A(flag, flag);
        break;
    }
}

int g1(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        B(flag, flag);
        break;
    }
}
