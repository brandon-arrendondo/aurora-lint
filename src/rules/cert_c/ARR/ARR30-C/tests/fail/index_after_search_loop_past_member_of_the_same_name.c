/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A loop counter's initial value is not its value after the loop
 *
 * The loop leaves `idx` anywhere from 0 to 8, and `s->idx` is a structure
 * member, not an assignment to `idx`. Reading `idx` as its initial 0
 * would miss the index past the end of `buf`.
 */

struct slot {
    int idx;
};

int find(const int *keys, int key, struct slot *s)
{
    int buf[4];
    int idx;
    for (idx = 0; idx < 8; idx++) {
        if (keys[idx] == key)
            break;
    }
    s->idx = idx;
    buf[idx] = 1;
    return buf[0];
}
