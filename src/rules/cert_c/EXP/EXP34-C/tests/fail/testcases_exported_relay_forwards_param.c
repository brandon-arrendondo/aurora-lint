/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - `apply3` guards `slot` and then dereferences it unguarded,
 *         and `relay3` is exported: a caller in a translation unit the
 *         prescan never saw may hand it a null.
 *
 * The sibling of the address-taken relay fixture, through the other way a
 * caller set is open. Reporting here needs the forwarded parameter's seed
 * to be withheld whenever it is not proven, rather than only when the
 * relay's address is taken -- an exported function's collected call sites
 * are a subset by definition, and the one spelled call site below passing
 * `&local` is not a proof about the ones in other files.
 */

void relay3(int *q);

static void apply3(int *slot)
{
    if (slot) {
        *slot = 1;
    }
    *slot = 2;
}

void relay3(int *q)
{
    apply3(q);
}

void configure3(void)
{
    int local = 0;

    relay3(&local);
}
