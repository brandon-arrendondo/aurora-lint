/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - the static sink's only caller passes a small constant
 *
 * The counterpart of static_sink_fed_rand_by_its_caller.c: the one caller
 * passes 2, so the parameter's value is known and the addition fits.
 */
static int sink(int data)
{
    return data + 1;
}

int caller(void)
{
    int data = 2;
    return sink(data);
}
