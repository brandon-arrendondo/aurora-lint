struct s { int a; };

int get(struct s *q);

int caller(void)
{
    struct s local = { 1 };
    return get(&local);
}
