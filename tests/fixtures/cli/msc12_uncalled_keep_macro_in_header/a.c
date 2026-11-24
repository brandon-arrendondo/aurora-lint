#include "compiler.h"

INIT_FN static void setup(void) { (void)0; }
static void KEEP_SYM kept(void) { (void)0; }
MY_CTOR_PRIO(101) static void early(void) { (void)0; }

static int check_it(int v) USED_FOR_ASSERTS_ONLY;
static int check_it(int v) { return v > 0; }

int api(int v) { return v; }
