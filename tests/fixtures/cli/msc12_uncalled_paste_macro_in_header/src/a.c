#include "pp.h"

static int foo_handler(void) { return 1; }
static int bar_handler(void) { return 2; }
static int baz_fn(void) { return 3; }

int api(void) { return PP_CAT(foo, _handler)() + PP_HANDLER(bar)() + PP_CALL_BAZ(); }
