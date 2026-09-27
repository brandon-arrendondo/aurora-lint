/*
 * Rule: EXP33-C
 * Source: custom
 * Status: PASS - Should NOT trigger EXP33-C violation
 * Description: for_each_link walks a list assigning its cursor when
 * WITH_LINKS is defined, and without it is `if (0)`, which never mentions
 * the cursor and makes the loop body dead. In neither build is link read
 * before it is written: the only reads are in the body.
 */

struct node {
    int id;
    struct node *next;
};

struct list {
    struct node *first;
};

int use_id(int id);

#ifdef WITH_LINKS
#define for_each_link(cursor, l) \
    for ((cursor) = (l)->first; (cursor); (cursor) = (cursor)->next)
#else
#define for_each_link(cursor, l) if (0)
#endif

void walk(struct list *l)
{
    struct node *link;

    for_each_link(link, l) {
        use_id(link->id);
    }
}
