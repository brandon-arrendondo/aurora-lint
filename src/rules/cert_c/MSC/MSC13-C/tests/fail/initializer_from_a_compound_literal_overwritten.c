/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - a compound literal at block scope is an object, not a constant expression, so it is no default, written out, through a macro, or built from a brace-list macro
 */

struct pair {
    int a;
    int b;
};

struct pair make(void);

int f(void)
{
    struct pair v = (struct pair){0};
    v = make();
    return v.a;
}

#define LITERAL(type) (type)
#define ORIGIN LITERAL(struct pair){ 0, 0 }

int g(void)
{
    struct pair v = ORIGIN;
    v = make();
    return v.b;
}

#define PAIR_INIT { 0, 0 }
#define LITERAL_OF(type, init) (type) init
#define ORIGIN_OF LITERAL_OF(struct pair, PAIR_INIT)
#define ORIGIN_CAST (struct pair) PAIR_INIT

int h(void)
{
    struct pair v = ORIGIN_OF;
    v = make();
    return v.a;
}

int k(void)
{
    struct pair v = ORIGIN_CAST;
    v = make();
    return v.b;
}

int m(void)
{
    struct pair v = (struct pair) PAIR_INIT;
    v = make();
    return v.a;
}
