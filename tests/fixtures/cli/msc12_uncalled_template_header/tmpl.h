/* A template: the including file defines hook() before including it. */
static inline int wrap(int v) { return hook(v) * 2; }
