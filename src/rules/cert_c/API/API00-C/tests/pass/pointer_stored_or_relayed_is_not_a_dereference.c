/*
 * Rule: API00-C
 * Source: custom
 * Status: PASS - Should NOT trigger API00-C violation
 * Description: The pointer-parameter shapes that never read or write through
 * the pointer (task 743), plus the one whose guard lives one frame down
 * (task 744).
 *
 * Storing a pointer in caller-owned memory, handing it to a registrar as an
 * opaque cookie, accepting and ignoring it, or comparing it against NULL are
 * all uses for which NULL is a perfectly good value -- the finding's premise
 * does not hold. Contrast tests/fail/wiki_noncompliant_1.c, where the store
 * is into FILE-SCOPE state and so outlives the call.
 */

struct handler {
    void (*fn)(void *);
    void *cookie;
};

struct conn {
    int client;
};

int register_handler(struct handler *h, void (*fn)(void *), void *cookie)
{
    if (h == 0)
        return -1;
    h->fn = fn;
    h->cookie = cookie;
    return 0;
}

/* Accepted and ignored outright -- hostap's xml_node_get_text ctx. */
const char *xml_node_get_text(struct conn *ctx, const char *text)
{
    return text;
}

/* Dead in the body but for an equality test, which is evidence of
   validation, not a dereference -- hostap's p2p_rx_action bssid. */
int p2p_rx_action(const unsigned char *bssid)
{
    return bssid == 0;
}

/* Task 744: the guard exists, one frame down. open_dict null-checks its
   argument before dereferencing it, so the forward is safe. */
int open_dict(struct conn *c)
{
    if (!c)
        return -1;
    return c->client;
}

int getter(struct conn *c)
{
    return open_dict(c);
}
