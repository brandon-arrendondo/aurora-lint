#ifndef SHAPES_H
#define SHAPES_H
int square(int x);
/* Evaluates its argument once. */
#ifndef SQ
#define SQ(x) square(x)
#endif
#endif
