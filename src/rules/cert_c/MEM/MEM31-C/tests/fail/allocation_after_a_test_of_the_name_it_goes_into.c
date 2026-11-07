/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A success test whose branch leaves says the name is empty on
 * the code below it, and an allocation there fills it again. When the block
 * goes unreleased, its return is reported, whether the name held a block
 * before the test or had only been looked up.
 */

#include <stdlib.h>

struct node {
    struct node *next;
};

char *lookup(int key);
void use(void);

int looked_up_then_returned(int key)
{
    char *p = lookup(key);
    if (p) {
        return 0;
    }
    p = malloc(8); /* Expect: here */
    if (p == NULL) {
        return -1;
    }
    use();
    return 0; /* Expect: here */
}

int looked_up_then_continued(int n)
{
    for (int i = 0; i < n; i++) {
        char *p = lookup(i);
        if (p != NULL) {
            continue;
        }
        p = malloc(8);
        if (p == NULL) {
            return -1;
        }
        use();
        return 1; /* Expect: here */
    }
    return 0;
}

int field_tested_then_filled(struct node *head)
{
    struct node *cur = head;
    if (cur->next != NULL) {
        return -1;
    }
    cur->next = malloc(sizeof(*cur->next)); /* Expect: here */
    if (cur->next == NULL) {
        return -1;
    }
    use();
    return 0; /* Expect: here */
}

int filled_again_after_the_returning_branch(void)
{
    char *p = malloc(8);
    if (p != NULL) {
        free(p);
        return 0;
    }
    p = malloc(8); /* Expect: here */
    use();
    return 1; /* Expect: here */
}
