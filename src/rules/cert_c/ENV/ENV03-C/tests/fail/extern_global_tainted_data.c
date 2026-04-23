// sqc-test: prescan
/*
 * Rule: ENV03-C
 * Source: testcases (Juliet v68 bad pattern)
 * Status: FAIL - Should trigger ENV03-C violation
 *
 * Non-static (extern-linkage) global pointer written by a tainted function
 * (reads from getenv). The sink reads the global through a local alias and
 * calls system() — should be flagged because the writer introduces taint.
 *
 * Mirrors Juliet CWE78 variant 68 badSink: tainted data passed via global
 * variable from one function to another in different source files.
 */

#ifdef _WIN32
#define GETENV getenv
#define SYSTEM system
#else
#define GETENV getenv
#define SYSTEM system
#endif

/* Non-static extern-linkage global pointer (Juliet v68 pattern) */
char *env03_v68_tainted_cmd;

/* Tainted writer: assigns data derived from getenv — introduces taint */
static void env03_v68_init_tainted(void) {
    char *env = GETENV("CMD");
    if (env != NULL) {
        env03_v68_tainted_cmd = env;
    }
}

/* Sink: reads global through local alias, calls system().
 * SHOULD be flagged: env03_v68_tainted_cmd is written by
 * env03_v68_init_tainted which has a taint source. */
static void env03_v68_execute_tainted(void) {
    char *data = env03_v68_tainted_cmd;
    /* POTENTIAL FLAW: tainted data reaches system() via global pointer */
    SYSTEM(data);
}
