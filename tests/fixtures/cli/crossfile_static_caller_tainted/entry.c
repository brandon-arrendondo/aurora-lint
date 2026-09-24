/* The only caller of relay(): a static whose name other.c also defines
 * static. This one passes the environment through. */
#include <stdlib.h>

void relay(char *cmd);

static void run(void)
{
    relay(getenv("CMD"));
}

void entry(void)
{
    run();
}
