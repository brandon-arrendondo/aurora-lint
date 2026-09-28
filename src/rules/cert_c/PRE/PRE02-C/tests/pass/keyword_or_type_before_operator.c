/*
 * Rule: PRE02-C
 * Source: testcases
 * Status: PASS - Should not trigger PRE02-C violation
 *
 * None of these replacement lists holds a binary operator. The - after
 * return and case is unary, and the * after a type name, or ending the
 * list, is part of a declarator or a dereference. None is an expression
 * that parentheses would make safer, and around most of them parentheses
 * would not compile.
 */

#include <errno.h>
#include <stddef.h>

struct node {
    struct node *next;
};

#define FAIL return -1
#define CHECK(x) if (!(x)) return -EINVAL
#define CASE_NEG case -1:
#define STR_T char *
#define NODE_PTR struct node *
#define SZ sizeof *p

int classify(int v, int *p)
{
    STR_T name = NULL;
    NODE_PTR head = NULL;
    CHECK(v != 0);
    switch (v) {
    CASE_NEG
        FAIL;
    default:
        break;
    }
    (void)name;
    (void)head;
    return (int)SZ;
}
