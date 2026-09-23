/*
 * Rule: MEM31-C
 * Source: task_580
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: seL4 generates its capability/page-table accessors at build time
 * from .bf spec files (tools/bitfield_gen.py). The generated `*_new`
 * constructors build a small struct on the stack and return it BY VALUE --
 * nothing is heap-allocated -- but they match is_allocation_call's `_new`
 * name-shape heuristic, so every one of them was reported as a leak (0/60 TP
 * in task 552's seL4 sample). A local declared with a plain declarator that
 * is never dereferenced, indexed or NULL-checked cannot hold heap memory, so
 * a name-heuristic-only "allocation" stored into it isn't tracked (task 580).
 */

typedef unsigned long word_t;

struct pte {
    word_t words[1];
};
typedef struct pte pte_t;

struct cap {
    word_t words[2];
};
typedef struct cap cap_t;

/* Declared here the way the generated header would declare them. */
pte_t pte_new(word_t addr, word_t flags);
cap_t cap_frame_cap_new(word_t base, word_t rights);
word_t cap_get_capType(cap_t cap);

void setPTE(pte_t *ptSlot, word_t addr)
{
    pte_t pte = pte_new(addr, 1);
    *ptSlot = pte;
}

word_t frameCapType(word_t base)
{
    cap_t cap = cap_frame_cap_new(base, 3);
    return cap_get_capType(cap);
}
