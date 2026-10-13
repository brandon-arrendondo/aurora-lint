/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: PASS - an if/else whose every path returns leaves nothing for the
 * break after it to do
 */

int g(int k, int x)
{
    switch (k) {
    case 1:
        return 1;
    default:
        if (x)
            return 2;
        else
            return 3;
        break;
    }
}
