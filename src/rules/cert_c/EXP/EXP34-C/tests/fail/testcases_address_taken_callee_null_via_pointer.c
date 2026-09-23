/*
 * Rule: EXP34-C
 * Source: testcases (aurora_lint 1465)
 * Status: FAIL - `handle_event` guards `port` and then dereferences it
 *         unguarded, and the null that reaches it arrives through the
 *         dispatch table, which names the function nowhere.
 *
 * The counterpart of the `pass` fixture for a proven-non-null parameter next
 * door. There, a static callee whose every call site guards its pointer is
 * genuinely non-null, so the guard is dead-defensive and the disjunct may be
 * discarded. Here the only DIRECT call site also hands over a stack address --
 * but the function's address sits in `handlers`, and code that calls it
 * through the table passes null. `has_internal_linkage` promises every caller
 * is in this translation unit, which is true and not the same as every caller
 * being spelled `handle_event(...)`; counting only the spelled ones turns a
 * subset into a proof and silences the real dereference.
 */

static void handle_event(int *port)
{
    if (port) {
        *port = 1;
    }
    *port = 2;
}

typedef void (*handler_t)(int *);

static handler_t handlers[] = {handle_event};

void dispatch(int which)
{
    int local_port = 0;

    handle_event(&local_port);
    handlers[which]((int *)0);
}
