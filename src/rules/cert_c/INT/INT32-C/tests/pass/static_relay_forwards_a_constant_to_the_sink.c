/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - a relay forwards its caller's constant to the sink
 *
 * The counterpart of static_relay_forwards_rand_to_the_sink.c: relay's one
 * caller passes 2, so the forwarded value is bounded at every hop.
 */
static int sink(int data)
{
    return data + 1;
}

static int relay(int data)
{
    return sink(data);
}

int caller(void)
{
    return relay(2);
}
