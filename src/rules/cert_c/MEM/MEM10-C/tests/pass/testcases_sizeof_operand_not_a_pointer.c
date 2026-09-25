/*
 * Rule: MEM10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM10-C violation
 */

/*
 * Rule: MEM10-C - Define and use a pointer validation function
 * Status: PASS
 * Reason: In each call `sizeof(x)` is the right size. `x` is a scalar
 *         parameter, a local array, a pointer whose own bytes the call
 *         copies (`&x` is also an argument), or a block-scope scalar that
 *         shadows a same-named pointer parameter. Only a pointer whose
 *         pointee was meant can make `sizeof(x)` the wrong size.
 *
 *         Distilled from valkey src/cluster_legacy.c, timeout.c, zipmap.c
 *         (scalar parameters), rax.c (pointer-field copies) and lzf_c.c
 *         (a local array).
 */

#include <stdint.h>
#include <string.h>

struct node {
    int v;
};

void put_u16(unsigned char *ext, uint16_t value)
{
    memcpy(ext, &value, sizeof(value));
}

void store_child(unsigned char *field, struct node *child)
{
    memcpy(field, &child, sizeof(child));
}

struct node *load_child(const unsigned char *field)
{
    struct node *h;
    memcpy(&h, field, sizeof(h));
    return h;
}

void clear_table(void)
{
    const unsigned char *htab[64];
    memset(htab, 0, sizeof(htab));
    (void)htab;
}

void shadowed(unsigned char *out, const char *len)
{
    (void)len;
    {
        unsigned int len = 4;
        memcpy(out, &len, sizeof(len));
    }
}

/* An array OF POINTERS sized by a pointer-typed element: sqlite json.c and
 * loadext.c. `n * sizeof(p)` and calloc's element size name one element. */
struct parse {
    int n;
};

void drop_entry(struct parse **a, int used, int i)
{
    struct parse *tmp = a[i];
    memmove(&a[i], &a[i + 1], (used - i - 1) * sizeof(tmp));
    (void)tmp;
}

void copy_handles(void **dst, void **src, int n)
{
    void *handle = src[0];
    memcpy(dst, src, sizeof(handle) * n);
}

/* The file's own configuration picks the array arm: valkey sha1.c. */
#define HANDSOFF

void transform(const unsigned char *buffer)
{
#ifdef HANDSOFF
    unsigned char block[64];
    memcpy(block, buffer, 64);
#else
    unsigned char *block = (unsigned char *)buffer;
#endif
    memset(block, '\0', sizeof(block));
}
