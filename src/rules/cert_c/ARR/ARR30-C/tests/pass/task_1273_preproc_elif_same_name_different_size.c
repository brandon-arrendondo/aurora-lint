/*
 * Rule: ARR30-C
 * Source: task 1273 (valkey src/server.c checkTcpBacklogSettings, lines
 *         2643-2659)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: two mutually exclusive `#elif` branches each declare `mib`, one
 *         with three elements and one with two, and each branch indexes
 *         only its own. `mib[2]` in the three-element branch was reported
 *         against the two-element declaration of the OTHER branch, which
 *         cannot coexist with it. A preprocessor conditional is textual,
 *         not a scope, so the declaration in force at `mib[2]` is the
 *         nearest preceding one -- `int somaxconn, mib[3]` -- and the
 *         lookup now resolves to it.
 *
 * Distinct from task 912's same-name-different-size conflict detector,
 * which covers `#ifdef`/`#else` pairs: that detector marks the size
 * unknown; here each branch's own declaration is resolvable and correct.
 */

int sysctl(int *name, unsigned namelen, void *oldp, unsigned long *oldlenp, void *newp,
           unsigned long newlen);

#define CTL_KERN 1
#define KERN_IPC 2
#define KIPC_SOMAXCONN 3
#define KERN_SOMAXCONN 4

int check_backlog(void)
{
    int somaxconn = 0;
#if defined(HAVE_PROC_SOMAXCONN)
    somaxconn = 128;
#elif defined(HAVE_SYSCTL_KIPC_SOMAXCONN)
    int mib[3];
    unsigned long len = sizeof(int);

    mib[0] = CTL_KERN;
    mib[1] = KERN_IPC;
    mib[2] = KIPC_SOMAXCONN;
    sysctl(mib, 3, &somaxconn, &len, 0, 0);
#elif defined(HAVE_SYSCTL_KERN_SOMAXCONN)
    int mib[2];
    unsigned long len = sizeof(int);

    mib[0] = CTL_KERN;
    mib[1] = KERN_SOMAXCONN;
    sysctl(mib, 2, &somaxconn, &len, 0, 0);
#endif
    return somaxconn;
}
