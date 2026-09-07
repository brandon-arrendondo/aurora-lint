/*
 * Rule: API00-C
 * Source: custom
 * Status: FAIL - SHOULD trigger API00-C violation
 * Description: An early-exit guard used to credit any parameter whose NAME
 * appeared in the condition TEXT (task 902). None of these conditions tests
 * its parameter for NULL, and each function dereferences the parameter
 * afterwards:
 *
 *   - `e == e->next` compares against another pointer and dereferences `e`
 *     on the way,
 *   - `*base != 0` tests the pointee, and `chdir(base)` is a use rather than
 *     a check,
 *   - the match was a substring rather than a word, so `ie` was credited by
 *     `update_dh_ie` appearing in the condition.
 */

struct node {
    struct node *next;
    int val;
};

int chdir(const char *path);

int walk(struct node *e)
{
    if (e == e->next)
        return 1;
    return e->val;
}

int enter(const char *base)
{
    if (*base != 0 && chdir(base))
        return -1;
    return *base;
}

int build_ies(unsigned char *ie, unsigned char *update_dh_ie)
{
    if (update_dh_ie == 0)
        return -1;
    return ie[0];
}
