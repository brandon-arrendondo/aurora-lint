/*
 * Rule: INT02-C
 * Source: regression
 * Status: PASS - `o->type != type` compares two ints
 *
 * `type` is an `unsigned` bit-field four bits wide. Every value it can hold
 * fits in an int, so the integer promotions make it an int before the
 * comparison (C11 6.3.1.1p2): no signed operand is converted to unsigned.
 * The struct is reached through a bodyless typedef, as the fields of a
 * header-defined object usually are.
 */

struct object {
    unsigned type : 4;
    unsigned encoding : 4;
    int refcount;
};

typedef struct object obj_t;

int check_type(obj_t *o, int type)
{
    return o && o->type != type;
}
