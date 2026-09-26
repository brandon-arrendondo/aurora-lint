/* The command reaches system() as a parameter of a static function, so
 * whether it is flagged depends on every caller up the chain. Its only
 * caller is a static whose name other.c also defines static; this one
 * passes a fixed command. */
#include <stdlib.h>

static void sink(char *cmd)
{
    system(cmd);
}

static void run(void)
{
    char cmd[] = "ls";
    sink(cmd);
}

void entry(void)
{
    run();
}
