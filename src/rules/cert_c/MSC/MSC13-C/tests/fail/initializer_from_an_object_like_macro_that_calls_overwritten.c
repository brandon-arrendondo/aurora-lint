/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - an object-like macro is a default only when its replacement list calls nothing and names no object: NOW_TICKS calls, SOCKERRNO names `errno` and CURRENT names a variable
 */

#include <errno.h>

int read_ticks(void);
int get(void);
int current_value;

#define NOW_TICKS read_ticks()
#define SOCKERRNO errno
#define CURRENT current_value

int ticks(void)
{
    int t = NOW_TICKS;
    t = get();
    return t;
}

int socket_error(void)
{
    int e = SOCKERRNO;
    e = get();
    return e;
}

int current(void)
{
    int x = CURRENT;
    x = get();
    return x;
}
