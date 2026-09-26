#include <stdlib.h>
struct s { int a, b, c; };
int sum(void)
{
    struct s *p = malloc(sizeof *p);
    p->a = 1;
    p->b = 2;
    p->c = 3;
    return p->a;
}
