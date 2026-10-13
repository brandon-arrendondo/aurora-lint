/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: PASS - a macro whose every path returns ends the arm, so the break
 * after it is dead and the switch ends the function's path
 */

#define FAIL() return -1
#define FAIL_BLOCK() do { return -1; } while (0)

int g(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        FAIL();
        break;
    }
}

int h(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        FAIL_BLOCK();
        break;
    }
}
