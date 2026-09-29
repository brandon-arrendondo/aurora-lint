#include <ctype.h>
#include <stdio.h>

int lower_next(const char **p)
{
    return tolower(*(*p)++);
}

int read_next(FILE **files)
{
    return getc(*files++);
}
