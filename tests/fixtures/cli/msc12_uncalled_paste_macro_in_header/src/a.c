#include "pp.h"

static int foo_handler(void) { return 1; }
static int bar_handler(void) { return 2; }

int api(void) { return PP_CAT(foo, _handler)() + PP_HANDLER(bar)(); }
