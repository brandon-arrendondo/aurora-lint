/* The command reaches system() as a parameter, so whether it is flagged
 * depends on every caller up the chain. */
#include <stdlib.h>

void sink(char *cmd)
{
    system(cmd);
}
