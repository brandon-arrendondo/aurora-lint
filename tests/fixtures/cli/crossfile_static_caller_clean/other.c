/* An unrelated static of the same name. It reads the environment, but it
 * never calls relay(), so it has no bearing on sink(). */
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
