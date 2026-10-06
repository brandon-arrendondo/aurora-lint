#include <stddef.h>

/* The two arms of one conditional declare `both` differently: an array in
 * one, an integer in the other. The reader must not pick an arm. */
#define DECL(A) extern A

#ifdef WIDE_BOTH
DECL(size_t both);
#else
DECL(char both[8]);
#endif
