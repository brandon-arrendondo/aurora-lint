/*
 * Rule: ARR32-C
 * Source: synthetic
 * Status: PASS - An array at file scope or in a struct is never variable-length
 *
 * Only a block can declare a variable-length array (C11 6.7.2.1p9,
 * 6.7.6.2p2), so an array at file scope or a struct member has a constant
 * size wherever it compiles, even where this file does not show the size
 * to be one: `sizeof(*hdr)` is not read through the pointer's type here.
 */
struct header { int kind; int len; };
extern struct header *hdr;

static int reserved[sizeof(*hdr) * 2];

struct message {
    unsigned char body[sizeof(*hdr) + 16];
};

void sink(void *p);

void use(void)
{
    struct message m;
    sink(&m);
    sink(reserved);
}
