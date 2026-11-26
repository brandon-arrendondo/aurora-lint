/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A pointer to an array is indexed within the dimensions it points to
 *
 * `int (*row)[4]` points to arrays of four and `int (*planes)[3][4]` to
 * arrays of three rows of four. Each access stays within those dimensions,
 * by a constant or by a loop, through the pointer and through its
 * dereference.
 */
int row_of_four[4];
int cube[2][3][4];

int last_element_of_the_row_pointed_to(void)
{
    int (*row)[4] = &row_of_four;
    return (*row)[3];
}

void every_element_of_the_row_pointed_to(void)
{
    int (*row)[4] = &row_of_four;
    for (int k = 0; k < 4; k++) {
        (*row)[k] = 0;
    }
}

int last_element_of_the_planes_pointed_to(void)
{
    int (*planes)[3][4] = cube;
    return planes[1][2][3];
}

int last_element_through_a_dereference(void)
{
    int (*planes)[3][4] = cube;
    return (*planes)[2][3];
}
