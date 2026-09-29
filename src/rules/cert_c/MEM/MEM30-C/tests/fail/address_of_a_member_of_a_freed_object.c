/*
 * Rule: MEM30-C
 * Source: real-world (sqlite ext/misc: a constructor frees the new object
 *         on failure and still stores &pNew->base in the out-parameter)
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: `&obj->base` computes from the value of `obj`, which the call
 * above released. Taking the address of a FIELD SLOT that holds a freed
 * pointer (`&o->h`) reads nothing freed; taking the address of a member of
 * a freed OBJECT uses the freed pointer.
 */
#include <stdlib.h>

struct base {
    int n;
};

struct object {
    struct base base;
    char *name;
};

static void object_free(struct object *p)
{
    if (p) {
        free(p->name);
        free(p);
    }
}

int object_connect(struct base **out)
{
    struct object *obj = calloc(1, sizeof(*obj));
    object_free(obj);
    *out = &obj->base;
    return 1;
}
