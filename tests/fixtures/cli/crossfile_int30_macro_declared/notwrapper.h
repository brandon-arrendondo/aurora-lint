#include <stddef.h>

/* A macro that does something with its argument is no declaration. */
#define REGISTER(A) register_object(A)

REGISTER(char reg[16]);
