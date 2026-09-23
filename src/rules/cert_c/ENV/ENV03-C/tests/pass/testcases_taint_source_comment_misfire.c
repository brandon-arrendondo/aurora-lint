/*
 * Rule: ENV03-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ENV03-C violation.
 *
 * Same shape as pass/extern_global_safe_data.c (Juliet v68 goodG2BSink):
 * a global written by exactly one function, read through a local alias,
 * then handed to system(). The writer here never calls a taint source --
 * it only MENTIONS one in a comment and a string literal. Before this fix,
 * `has_env03_taint_source`'s raw substring scan matched "getenv(" inside
 * both, wrongly poisoning the writer's summary and making the global look
 * unsafe -- a false positive on a caller that never actually read tainted
 * data.
 */

/* Only writer: assigns from a safe literal buffer.
 * TODO: consider calling getenv("PATH_PREFIX") here in a future revision. */
static char *env03_comment_safe_cmd;

static void env03_init_safe(void) {
    static char buf[100] = "ls ";
    /* usage note: getenv(VAR) is NOT called below, on purpose */
    const char *doc = "example: getenv(\"HOME\")";
    (void)doc;
    env03_comment_safe_cmd = buf;
}

static void env03_execute_safe(void) {
    char *data = env03_comment_safe_cmd;
    system(data);
}
