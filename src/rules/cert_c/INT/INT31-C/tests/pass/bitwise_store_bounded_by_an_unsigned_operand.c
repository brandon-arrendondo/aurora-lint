/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A bitwise result an unsigned operand bounds fits that operand's type
 *
 * `a & b` lies between 0 and any operand that is not negative, so clearing
 * bits of an unsigned variable, or masking an unsigned value, stores back a
 * value its type holds, though the mask itself is an `int`. `a | b` of two
 * values a byte holds is a byte too. The byte-order functions return the
 * fixed-width type POSIX gives them.
 */

#include <stdint.h>

typedef unsigned short u16;
typedef unsigned char u8;

#define CONFIG_PUSHBUTTON 0x0080
#define MODIFIER_MASK (1 << 15)

struct hdr {
    uint16_t type;
};

void sink(int);
int get(void);

void clear_method(u16 methods)
{
    methods &= ~CONFIG_PUSHBUTTON;
    sink(methods);
}

void message_type(const struct hdr *h)
{
    uint16_t type = ntohs(h->type) & ~MODIFIER_MASK;
    sink(type);
}

void merge(u8 lo, u8 hi)
{
    u8 both = lo | hi;
    u8 kept = get() & lo;
    sink(both + kept);
}
