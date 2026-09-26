/* An unrelated static of the same name. It reads the environment, but it
 * never calls sink(), so it has no bearing on it. */
#include <stdlib.h>

static void run(void)
{
    char *home = getenv("HOME");
    (void)home;
}

void other(void)
{
    run();
}
