#include <stddef.h>

#define DECLARE(A) extern A

/* The argument list never closes. */
DECLARE(char junk[16]
