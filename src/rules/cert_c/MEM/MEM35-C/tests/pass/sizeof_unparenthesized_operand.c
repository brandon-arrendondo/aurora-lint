#include <stdlib.h>

struct pool { char mark[4]; };
struct node { int a; };

void f(struct pool *pool, size_t cb)
{
  struct node *new = malloc(cb + (sizeof *new) + (sizeof pool->mark));
  free(new);
}
