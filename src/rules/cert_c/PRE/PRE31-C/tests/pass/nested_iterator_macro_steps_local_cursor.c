/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: for_each_id hands its cursor parameter on to for_each_node,
 * which assigns it, and find passes its own local there. The loop writes
 * only find's own storage, so find changes nothing a caller can see.
 */

#define TWICE(x) ((x) + (x))

struct node {
    struct node *next;
    int id;
};

#define for_each_node(pos, head) \
    for ((pos) = (head); (pos) != 0; pos = (pos)->next)

#define for_each_id(pos, head, want) \
    for_each_node(pos, head) if ((pos)->id == (want))

int find(const struct node *head, int want) {
    const struct node *n;
    for_each_id(n, head, want) {
        return 1;
    }
    return 0;
}

int use(const struct node *head) {
    return TWICE(find(head, 3));
}
