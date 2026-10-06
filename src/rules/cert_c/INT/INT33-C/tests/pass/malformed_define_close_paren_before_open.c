#include <stddef.h>

/* A malformed #define whose ")" precedes its "(" used to panic the whole scan. */
#define BAD) (a) / (b)

int main(void) { return 0; }
