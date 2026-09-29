/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: for_each_node assigns its cursor parameter, and count passes its
 * own local there, so the loop writes only count's own storage. count
 * changes nothing a caller can see.
 */

#define TWICE(x) ((x) + (x))

struct node {
    struct node *next;
};

#define for_each_node(pos, head) \
    for ((pos) = (head); (pos) != 0; pos = (pos)->next)

int count(const struct node *head) {
    const struct node *n;
    int total = 0;
    for_each_node(n, head) {
        total++;
    }
    return total;
}

int use(const struct node *head) {
    return TWICE(count(head));
}
