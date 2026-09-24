/*
 * Description: taking the address of a field through a cast alias and
 * handing it to a writer does not read the caller's object
 *
 * `&alias->field` names storage without touching it; the helper fills it.
 * The callee never reads through its parameter, so the caller's buffer is
 * not read uninitialized.
 */
#include <string.h>

struct addr {
    unsigned char bytes[4];
};

static void fill(unsigned char *out)
{
    memcpy(out, "abcd", 4);
}

static void parse(void *storage)
{
    struct addr *const a = (struct addr *)storage;
    fill(&a->bytes[0]);
}

int caller(void)
{
    struct addr a;
    parse(&a);
    return a.bytes[0];
}
