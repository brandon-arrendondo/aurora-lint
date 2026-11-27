/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: A block stored into a member of a file-scope object, or of
 * one a local `extern` declaration names, is still reachable through that
 * object after the function returns, whatever the object's storage class.
 */
#include <stdlib.h>
#include <string.h>

struct s {
    char *x;
};

static struct s file_static;
struct s file_global;

int into_a_static_object(const char *v)
{
    file_static.x = strdup(v);
    if (file_static.x == NULL)
        return -1;
    return 0;
}

int into_a_global_object(const char *v)
{
    file_global.x = strdup(v);
    return file_global.x != NULL;
}

int into_an_extern_object(const char *v)
{
    extern struct s elsewhere;

    elsewhere.x = strdup(v);
    return elsewhere.x != NULL;
}
