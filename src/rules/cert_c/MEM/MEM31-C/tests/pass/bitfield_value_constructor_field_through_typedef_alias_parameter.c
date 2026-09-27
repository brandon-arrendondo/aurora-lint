/*
 * Rule: MEM31-C
 * Source: real-world regression
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * seL4's fastpath shape: a bitfield value constructor stored into a by-value
 * field of a struct reached through a `cte_t *` parameter, where `cte_t` is a
 * BODYLESS `typedef struct cte cte_t;` apart from the body. `cap` holds a
 * `cap_t` by value, so nothing stored there is heap memory.
 */

typedef struct cap cap_t;
struct cap {
    unsigned long w[2];
};

typedef struct cte cte_t;
struct cte {
    cap_t cap;
};

cap_t cap_null_cap_new(void);

void f(cte_t *callerSlot)
{
    callerSlot->cap = cap_null_cap_new();
}
