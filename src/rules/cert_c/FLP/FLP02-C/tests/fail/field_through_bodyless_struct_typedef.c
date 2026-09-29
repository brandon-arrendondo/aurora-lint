/*
 * Rule: FLP02-C
 * Source: regression
 * Status: FAIL - `p->ratio == target` compares two doubles
 *
 * `gauge_t` is a bodyless typedef of `struct gauge`, whose fields are
 * declared under the tag. The field is found through the alias.
 */

struct gauge {
    double ratio;
};

typedef struct gauge gauge_t;

int at_target(const gauge_t *p, double target)
{
    return p->ratio == target;
}
