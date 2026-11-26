/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A pointer to an array is indexed past a dimension it points to
 * Expect: count=5
 *
 * `int (*row)[4]` points to arrays of four, so `(*row)[k]` is bounded by
 * four, and `int (*planes)[3][4]` points to arrays of three rows of four,
 * so its second subscript is bounded by three and its third by four. Each
 * access passes one of those dimensions by one: a constant, a loop that
 * runs to four, and the second and third subscripts through both the
 * pointer and its dereference.
 */
int row_of_four[4];
int cube[2][3][4];

int past_the_end_of_the_row_pointed_to(void)
{
    int (*row)[4] = &row_of_four;
    return (*row)[5]; /* Expect: here */
}

void loop_one_past_the_end_of_the_row_pointed_to(void)
{
    int (*row)[4] = &row_of_four;
    for (int k = 0; k <= 4; k++) {
        (*row)[k] = 0; /* Expect: here */
    }
}

int past_the_last_dimension_of_the_planes_pointed_to(void)
{
    int (*planes)[3][4] = cube;
    return planes[1][2][4]; /* Expect: here */
}

int past_the_middle_dimension_of_the_planes_pointed_to(void)
{
    int (*planes)[3][4] = cube;
    return planes[1][3][0]; /* Expect: here */
}

int past_the_last_dimension_through_a_dereference(void)
{
    int (*planes)[3][4] = cube;
    return (*planes)[2][4]; /* Expect: here */
}
