/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - `apply` guards `port` and then dereferences it unguarded,
 *         and the null that reaches it comes through the dispatch table,
 *         one hop further out than the table entry itself.
 *
 * `relay`'s address sits in `handlers`, so code that names it nowhere can
 * hand it a null; that is what an earlier fix already established for a
 * table entry's own parameters. This is the same incompleteness one hop
 * upstream. `relay`'s only spelled call site passes `&local`, so the
 * majority vote in `callsite_param_null_states` reads `q` as NotNull --
 * which says only "no caller I collected passes a null here". Seeding that
 * vote into `relay`'s body and then recording the forwarded `q` as a call
 * site's argument turns it into evidence, and counting that evidence proves
 * `apply`'s parameter non-null. An assumption about one function's callers
 * became a proof about the next one's, and the dereference the rule exists
 * to catch went unreported.
 *
 * Only the proof is withheld, never a null disjunct: a `PossiblyNull` vote
 * still seeds, so nothing in the other direction is lost. The `pass`
 * fixture next door is the control -- a relay whose caller set really is
 * closed keeps its proof and reports nothing.
 */

static void apply(int *port)
{
    if (port) {
        *port = 1;
    }
    *port = 2;
}

static void relay(int *q)
{
    apply(q);
}

typedef void (*handler_t)(int *);

static handler_t handlers[] = {relay};

void dispatch(int which)
{
    int local = 0;

    relay(&local);
    handlers[which]((int *)0);
}
