typedef int (*fn)(int);

static int helper(int v) { return v + 1; }
static int other_helper(int v) { return v + 2; }

#define X(name) name,
static const fn table[] = {
#include "fns.def"
};
#undef X

int run(int i, int v) { return table[i](v); }
