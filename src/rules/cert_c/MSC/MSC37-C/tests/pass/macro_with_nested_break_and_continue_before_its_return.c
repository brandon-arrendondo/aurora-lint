/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: PASS - a break or continue aimed at a loop or switch nested inside
 * the macro stays inside it, so the macro still returns on every path and the
 * break after it is dead
 */

#define LOOP_FAIL(x) do { for (;;) { if (x) break; } return -1; } while (0)
#define SWITCH_FAIL(x) do { switch (x) { case 1: break; default: break; } return -1; } while (0)
#define CONTINUE_FAIL(x) do { while (x) { continue; } return -1; } while (0)
#define INNER_FAIL(x) do { do { if (x) break; } while (0); return -1; } while (0)
#define FOR_FAIL(n) do { for (int i = 0; i < n; i++) { continue; } return -1; } while (0)
#define LOCAL_GOTO_FAIL() do { goto done; done: return -1; } while (0)

int a(int k, int x)
{
    switch (k) {
    case 1:
        return 1;
    default:
        LOOP_FAIL(x);
        break;
    }
}

int b(int k, int x)
{
    switch (k) {
    case 1:
        return 1;
    default:
        SWITCH_FAIL(x);
        break;
    }
}

int c(int k, int x)
{
    switch (k) {
    case 1:
        return 1;
    default:
        CONTINUE_FAIL(x);
        break;
    }
}

int d(int k, int x)
{
    switch (k) {
    case 1:
        return 1;
    default:
        INNER_FAIL(x);
        break;
    }
}

int e(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        FOR_FAIL(3);
        break;
    }
}

int f(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        LOCAL_GOTO_FAIL();
        break;
    }
}
