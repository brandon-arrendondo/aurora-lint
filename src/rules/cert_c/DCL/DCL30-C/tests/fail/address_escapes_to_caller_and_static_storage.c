/*
 * Rule: DCL30-C
 * Status: FAIL - Should trigger DCL30-C violation
 * Reason: The address of an automatic object stored where it outlives the
 *         call: through an output parameter's pointee, into a member of a
 *         file-scope object, into a static local, and a compound literal or
 *         a conditional that may yield a local buffer, returned.
 */

struct holder { int *p; };

static struct holder file_holder;

void through_out_member(struct holder *out)
{
    int x = 0;
    out->p = &x;            /* VIOLATION */
}

void through_out_pointer(int **out)
{
    int arr[4] = {0};
    *out = arr;             /* VIOLATION */
}

void into_file_object(void)
{
    int x = 0;
    file_holder.p = &x;     /* VIOLATION */
}

int *into_static_local(void)
{
    static int *keep;
    int x = 0;
    keep = &x;              /* VIOLATION */
    return 0;
}

int *compound_literal(void)
{
    return (int[]){1, 2, 3};    /* VIOLATION */
}

char *conditional(int c)
{
    char buf[8];
    return c ? buf : (char *)0; /* VIOLATION */
}
