/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * The doc comment says `p` must not be NULL, and the only caller passes an
 * unchecked malloc() result. A project's own documented precondition is
 * not proof (ADR-0011): C has no contract language that makes the caller
 * honour it, so the callee's dereference of a possibly-null argument is
 * reported.
 */
#include <stdlib.h>

struct item { int v; };

/**
 * \brief Read an item's value.
 * \param p The item. It must not be NULL.
 */
int item_value(struct item *p)
{
    return p->v;
}

int make_and_read(void)
{
    struct item *it = malloc(sizeof *it);
    return item_value(it);
}
