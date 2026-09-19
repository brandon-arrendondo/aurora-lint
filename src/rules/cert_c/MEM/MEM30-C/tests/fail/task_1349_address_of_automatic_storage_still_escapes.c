/*
 * Rule: MEM30-C
 * Source: task 1349 (companion to pass/task_1349_write_through_global_and_local_pointer_are_not_escapes.c)
 * Status: FAIL - Should trigger MEM30-C violation
 * Reason: Reading the escape from declarators must keep every real one: a
 *         local array or VLA decaying into a global pointer, and `&` of a
 *         local object, a member of it, an element of a local array, or a
 *         parameter object -- all automatic storage that dies with the
 *         call while the global keeps pointing at it.
 */

struct node { int flags; long epoch; };

char *gbuf;
int *gint;
struct node *gnode;

void array_decays(int n)
{
    char buf[64];
    char vla[n];
    gbuf = buf;             /* VIOLATION */
    gbuf = (char *)vla;     /* VIOLATION */
}

void address_of_local(struct node param)
{
    struct node local;
    int arr[4];
    gnode = &local;         /* VIOLATION */
    gint = &arr[1];         /* VIOLATION */
    gint = &local.flags;    /* VIOLATION */
    gnode = &param;         /* VIOLATION: a parameter is automatic too */
}
