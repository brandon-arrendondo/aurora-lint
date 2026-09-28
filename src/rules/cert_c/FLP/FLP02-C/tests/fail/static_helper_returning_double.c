/*
 * Rule: FLP02-C
 * Source: regression
 * Status: FAIL - `r == ceil2(r)` compares two doubles
 *
 * ceil2 is a static function this file defines, with no separate prototype;
 * its definition gives the call's return type, double.
 */

static double ceil2(double v)
{
    return (double)(long)(v + 0.999);
}

int is_whole(double r)
{
    return r == ceil2(r);
}
