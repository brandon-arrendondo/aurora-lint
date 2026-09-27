/*
 * Compiled as part of main.c, which #includes this file, so main.c's calls
 * reach this static die().
 */
#include <stdlib.h>

static void die(void) { exit(1); }
