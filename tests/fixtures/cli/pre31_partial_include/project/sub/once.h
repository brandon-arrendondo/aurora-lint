#ifndef ONCE_H
#define ONCE_H
int cube(int x);
/* Evaluates its argument once. */
#ifndef CUBE
#define CUBE(x) cube(x)
#endif
#endif
