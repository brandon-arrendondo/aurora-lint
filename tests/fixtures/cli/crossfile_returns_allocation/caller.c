/*
 * Cross-file returns_allocation test — caller (task 1343).
 * thing_ctor() is a header-defined (static inline) constructor: it calls
 * os_zalloc(), itself header-defined, and returns the result. Its name
 * matches none of MEM31-C's allocator-name heuristics, so flagging the
 * leak below can only come from the returns_allocation summary. Both
 * functions are resolved only via #include + -I (not -d), so crediting
 * thing_ctor() with returns_allocation depends on propagate_returns_
 * allocation rerunning in resolve_includes's re-propagation block.
 * The allocation is never freed here — a leak MEM31-C must catch.
 */
#include "constructor.h"

void leaks_the_constructed_thing(void) {
    struct thing *t = thing_ctor();
    t->value = 1;
}
