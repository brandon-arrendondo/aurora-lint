static int hook(int v) { return v + 1; }

#include "tmpl.h"

int api(int v) { return wrap(v); }
