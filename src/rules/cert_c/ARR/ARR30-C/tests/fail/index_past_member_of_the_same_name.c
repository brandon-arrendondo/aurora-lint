/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A member's assignment is not the index's value
 *
 * `p->i = 2` stores into a structure member that shares the index's name.
 * The local `i` still holds 9.
 */

struct counter {
    int i;
};

int fill(struct counter *p)
{
    int buf[4];
    int i = 9;
    p->i = 2;
    buf[i] = 1;
    return buf[0];
}
