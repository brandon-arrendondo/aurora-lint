/* This file's own TWICE, live only in this translation unit. */
#define TWICE(x) ((x) + (x))

int doubled(int v)
{
    return TWICE(v);
}
