/*
 * Rule: ENV03-C
 * Source: testcases (Juliet v68 good pattern)
 * Status: PASS - Should NOT trigger ENV03-C violation
 *
 * Non-static (extern-linkage) global pointer written only by a clean function.
 * The sink reads the global through a local alias and calls system() — should
 * be suppressed because every writer of the global is taint-free.
 *
 * Mirrors Juliet CWE78 variant 68 goodG2BSink: data passed as a global
 * variable from one function (clean writer) to another (sink) in different
 * source files.
 */

#ifdef _WIN32
#define SYSTEM system
#else
#define SYSTEM system
#endif

/* Non-static extern-linkage global pointer (Juliet v68 pattern) */
char *env03_v68_safe_cmd;

/* Only writer: assigns from a safe literal buffer — no taint source */
static void env03_v68_init_safe(void) {
    static char buf[100] = "ls ";
    env03_v68_safe_cmd = buf;
}

/* Sink: reads global through local alias, calls system().
 * Should NOT be flagged: env03_v68_safe_cmd is only written by
 * env03_v68_init_safe whose summary has no taint source. */
static void env03_v68_execute_safe(void) {
    char *data = env03_v68_safe_cmd;
    SYSTEM(data);
}
