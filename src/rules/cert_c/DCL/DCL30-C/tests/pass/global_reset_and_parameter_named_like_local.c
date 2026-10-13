/*
 * Rule: DCL30-C
 * Status: PASS - Should NOT trigger DCL30-C violation
 * Reason: A file-scope prototype whose parameter is spelled like a local is
 *         not a global object of that name, and a pointer holding heap
 *         memory is not an automatic address. A global that held a local's
 *         address only until it is reset before the function returns never
 *         outlives the object. Storing into a local struct or through a
 *         local pointer reaches nothing that outlives the call.
 */

#include <stdlib.h>

static void split(char **token);

static int *current;

void reset_before_return(void)
{
    int x = 0;
    current = &x;
    (void)*current;
    current = NULL;
}

void parameter_named_like_local(void)
{
    char *token;
    char *saveptr = malloc(8);
    token = saveptr;
    split(&token);
}

struct holder { int *p; };

void local_struct_and_local_pointer(void)
{
    int x = 0;
    struct holder h;
    struct holder *hp = &h;
    h.p = &x;
    hp->p = &x;
}
