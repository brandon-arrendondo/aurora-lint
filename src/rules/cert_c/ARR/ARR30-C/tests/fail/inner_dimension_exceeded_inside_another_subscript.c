/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A subscript inside another passes its last dimension
 * Expect: count=2
 *
 * `cube[0][0][4]` passes the last dimension of `int cube[2][3][4]`, and is
 * reported once, not once for each subscript around it. Its value, used as
 * the first subscript of the enclosing access, is unproven against the
 * first dimension and is reported once in its own right.
 */
int cube[2][3][4];

int past_the_last_dimension_inside_a_subscript(void)
{
    return cube[cube[0][0][4]][0][0];
}
