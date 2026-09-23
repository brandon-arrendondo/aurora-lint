/*
 * Rule: ARR30-C
 * Source: task 1278
 * Status: FAIL - `a[res]` after `res = other` is unchecked; the guard above
 *         bounded the OLD value of `res`.
 *
 * The preceding-guard proof is a fact about the variable at the guard, and
 * an assignment between the guard and the access discards it. Twin of the
 * early-return PASS fixture with the one line that breaks it.
 */

int rd(void);

int fill(int other)
{
    char a[128];
    int res = rd();

    if (res < 0 || (size_t) res >= sizeof(a))
        return -1;
    res = other;
    a[res] = '\0';
    return 0;
}
