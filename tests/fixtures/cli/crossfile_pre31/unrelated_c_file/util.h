#ifndef UTIL_H
#define UTIL_H

int twice_fn(int value);

/* Evaluates its argument once. */
#define TWICE(x) twice_fn(x)

#endif
