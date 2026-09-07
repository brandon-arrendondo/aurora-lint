/*
 * Rule: MSC12-C
 * Status: PASS - a bare-dereference busy-wait on a VOLATILE object is a real
 *         poll, not a forgotten loop body. A volatile read cannot be hoisted
 *         out of the loop, so the condition re-reads the object every
 *         iteration by definition and the empty body is the idiom. Every
 *         declaration below is at FILE scope, which is where seL4 puts the
 *         objects its busy-waits poll (kernel/boot.c, machine/l2c_310.c).
 */

struct l2cc_maintenance {
    unsigned int clean_inv_way;
};

struct l2cc_map {
    struct l2cc_maintenance maintenance;
};

static volatile int node_boot_lock;
volatile struct l2cc_map *const l2cc = (volatile struct l2cc_map *)0x4000000;

void wait_for_boot_lock(void)
{
    /* bare identifier read, no operator and no indirection at all */
    while (!node_boot_lock);
}

void clean_invalidate_l2(void)
{
    /* bare field read through a volatile pointer, no operator */
    while (l2cc->maintenance.clean_inv_way);
}

void wait_for_local_flag(volatile unsigned int *reg)
{
    /* the volatile qualifier is on a parameter, not a file-scope object */
    while (!*reg) {
    }
}
