/*
 * Rule: MSC17-C
 * Source: task_633
 * Status: FAIL - Should trigger MSC17-C violation
 */

/*
 * Rule: MSC17-C - Finish every set of statements associated with a case
 * label with a break statement
 * Status: FAIL
 * Reason: a #if/#ifdef with NO #else can compile away to nothing, same as
 * an if-statement with no else -- so it must never be treated as
 * terminating, even though its one branch ends in break.
 */

int handle(int op, int fd) {
    switch (op) {
    case 1: {
#if defined(FEATURE_A)
        fd = 1;
        break;
#endif
    }
    default:
        break;
    }
    return fd;
}
