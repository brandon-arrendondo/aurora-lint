#include <ctype.h>

/* The project's own tolower is judged by its body, not the standard's. */
#undef tolower
#define tolower(c) ((c) >= 'A' && (c) <= 'Z' ? (c) + 32 : (c))

int lower_next(const char **p)
{
    return tolower(*(*p)++);
}
