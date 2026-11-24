/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Every write that reaches the access is in bounds
 *
 * The initializer 9 is overwritten on both ways of the if/else and in
 * every case of the switch, with values inside `buf[5]`, before the access.
 */

int if_else(int c)
{
    int buf[5] = {0};
    int i = 9;
    if (c)
        i = 1;
    else
        i = 2;
    return buf[i];
}

int every_case(int c)
{
    int buf[5] = {0};
    int i = 9;
    switch (c) {
    case 1:
        i = 3;
        break;
    default:
        i = 4;
        break;
    }
    return buf[i];
}
