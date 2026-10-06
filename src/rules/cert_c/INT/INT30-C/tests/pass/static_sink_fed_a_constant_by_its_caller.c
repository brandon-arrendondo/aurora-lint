/*
 * Rule: INT30-C
 * Source: regression
 * Status: PASS - the static sink's only caller passes a small constant
 *
 * The counterpart of static_sink_fed_a_parsed_value_by_its_caller.c: the
 * one caller passes 2u, so the addition cannot wrap.
 */
static unsigned int sink(unsigned int data)
{
    return data + 1u;
}

unsigned int caller(void)
{
    unsigned int data = 2u;
    return sink(data);
}
