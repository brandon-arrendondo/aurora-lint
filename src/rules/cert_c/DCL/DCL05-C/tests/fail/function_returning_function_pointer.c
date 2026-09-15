/*
 * Rule: DCL05-C
 * Source: wiki (signal() shape, variants)
 * Status: FAIL - Should trigger DCL05-C violation
 *
 * A declarator whose return type is itself a pointer to a function nests one
 * function type inside another: the shape CERT's noncompliant example has.
 */

static void handler(int sig) { (void)sig; }

/* Definition, not just a prototype. */
static void (*get_handler(int which))(int)
{
    (void)which;
    return handler;
}

/* Pointer to a function returning a pointer to a function. */
int (*(*dispatch)(int))(void);
