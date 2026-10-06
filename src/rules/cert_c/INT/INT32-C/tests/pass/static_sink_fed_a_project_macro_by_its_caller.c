/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - the static sink's only caller passes a small macro constant
 *
 * The counterpart of static_sink_fed_a_limit_macro_by_its_caller.c: STEP
 * folds to 2, so the parameter's value is known and the addition fits.
 */
#define STEP 2

static int sink(int data)
{
    return data + 1;
}

int caller(void)
{
    return sink(STEP);
}
