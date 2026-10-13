/*
 * Rule: DCL30-C
 * Status: PASS - Should NOT trigger DCL30-C violation
 * Reason: Each store of a local's address into longer-lived storage is
 *         undone before the block holding it is left: reset in the same
 *         case of a switch, restored after a call that used it, or undone
 *         by assigning the whole containing object. A break or continue
 *         that only leaves an inner loop does not skip the reset.
 */

struct hook { void *ctx; int (*fn)(void *); };
struct session { struct hook hook; };
struct db { int *pnBytesFreed; void *pCtx; };

void use(void *p);

int status(struct db *db, int op, int n)
{
    switch (op) {
    case 1: {
        int nByte = 0;
        db->pnBytesFreed = &nByte;
        for (int i = 0; i < n; i++) {
            if (i == 3)
                break;
            use(db);
        }
        db->pnBytesFreed = 0;
        return nByte;
    }
    default:
        break;
    }
    return 0;
}

void walk(struct db *db)
{
    int ctx = 0;
    void *saved = db->pCtx;
    db->pCtx = &ctx;
    use(db);
    db->pCtx = saved;
}

void with_hook(struct session *s)
{
    struct hook saved = s->hook;
    int stat = 0;
    s->hook.ctx = &stat;
    use(s);
    s->hook = saved;
}
