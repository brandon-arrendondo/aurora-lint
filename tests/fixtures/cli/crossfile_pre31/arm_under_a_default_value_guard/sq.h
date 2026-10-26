#ifndef SQ_H
#define SQ_H
#ifndef SQ_FAST
#define SQ_FAST 1
#endif
int sq_fn(int);
#ifdef SQ_FAST
#define sq(x) sq_fn(x)
#else
#define sq(x) ((x) * (x))
#endif
#endif
