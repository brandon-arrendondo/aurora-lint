/*
 * Rule: ENV33-C
 * Source: testcases
 * Status: FAIL - Should trigger ENV33-C violation
 */

/*
 * Rule: ENV33-C - Do not call system()
 * Status: FAIL
 * Reason: The static sink's only caller has no taint source in its body, but
 * it is an exported relay that forwards its own parameter: whatever a caller
 * outside the scanned source passes to run_command() reaches system(). A
 * clean-bodied caller proves nothing while its own caller set is open.
 */

#include <stdlib.h>

static void execute(const char *cmd)
{
    system(cmd);
}

void run_command(const char *cmd)
{
    execute(cmd);
}
