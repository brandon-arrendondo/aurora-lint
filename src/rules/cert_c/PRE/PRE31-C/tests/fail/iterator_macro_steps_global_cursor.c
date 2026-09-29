/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: for_each_node assigns its cursor parameter, and count passes the
 * global cursor there, so count writes cursor: a proven side effect.
 */

#define TWICE(x) ((x) + (x))

struct node {
    struct node *next;
};

#define for_each_node(pos, head) \
    for ((pos) = (head); (pos) != 0; pos = (pos)->next)

const struct node *cursor;

int count(const struct node *head) {
    int total = 0;
    for_each_node(cursor, head) {
        total++;
    }
    return total;
}

int use(const struct node *head) {
    return TWICE(count(head));  // VIOLATION
}
