#include <stddef.h>

/* Objects declared through a wrapper macro: `extern A` where the object is
 * only declared, `A` where it is defined. */
#ifdef DEFINE_GLOBALS
# define GLOBAL0(A) A
#else
# define GLOBAL0(A) extern A
#endif

GLOBAL0(char cmd[64 + 32U]);
GLOBAL0(size_t total);
