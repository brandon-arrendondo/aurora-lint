/*
 * Rule: ENV33-C
 * Source: custom
 * Status: FAIL - Should trigger ENV33-C violation
 * Description: RUN_CMD is `system` when UNSANDBOXED is defined and a
 * sandboxed runner otherwise. The UNSANDBOXED build passes a string built
 * from the environment to system(). Taking the last definition met resolved
 * RUN_CMD to the sandboxed runner in every build.
 */

#include <stdlib.h>

int sandbox_run(const char *cmd);

#ifdef UNSANDBOXED
#define RUN_CMD system
#else
#define RUN_CMD sandbox_run
#endif

void run_editor(void)
{
    const char *cmd = getenv("EDITOR");
    RUN_CMD(cmd);
}
