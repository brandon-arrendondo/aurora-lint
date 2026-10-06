/* Objects a translation unit receives only through this header. */
#include <stddef.h>

extern char cmd[64];     /* an array: `cmd + n` is pointer arithmetic */
extern size_t total;     /* an integer: `total + n` is an unsigned sum */
extern char shared[8];   /* an array here ... */
