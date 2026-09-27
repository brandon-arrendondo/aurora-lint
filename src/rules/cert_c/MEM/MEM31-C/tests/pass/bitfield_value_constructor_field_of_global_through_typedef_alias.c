/*
 * Rule: MEM31-C
 * Source: real-world regression
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * Same bitfield-generator value-constructor pattern as elsewhere, stored into
 * a by-value field of a struct reached through a file-scope pointer. The
 * constructor is declared only in a header generated at build time, so no
 * return type is visible; the destination's declared field type is the
 * evidence. `cap` in `struct cte` holds a `cap_t` by value, so nothing stored
 * there can be heap memory.
 *
 * Two things have to line up for the field type to resolve. The base is a
 * file-scope variable, declared by no local in the assigning function, so its
 * type comes from its own declaration. And that declaration spells the struct
 * as `cte_t`, a BODYLESS `typedef struct cte cte_t;` apart from the body, so
 * the fields filed under the tag `cte` must also answer for the alias.
 */

typedef unsigned long word_t;

typedef struct cap cap_t;
struct cap {
    word_t words[2];
};

typedef struct cte cte_t;
struct cte {
    cap_t cap;
};

static volatile cte_t *slot_regs = (volatile cte_t *)0x1000;

void clear_slot(void)
{
    slot_regs->cap = cap_null_cap_new();
}
