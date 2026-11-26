/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A subscript passes the dimension it indexes
 * Expect: count=8
 *
 * Each access passes one dimension of a multidimensional array by one, and
 * is reported once, against that dimension's own size: the last, middle
 * and first of `int cube[2][3][4]`, the last of a local cube, both of
 * `int grid[3][4]`, a loop that runs one past the last dimension, and a
 * pointer to rows of `grid` that steps past its last row.
 */
int cube[2][3][4];
int grid[3][4];

int past_the_last_dimension_of_a_cube(void)
{
    return cube[1][2][4];
}

int past_the_middle_dimension_of_a_cube(void)
{
    return cube[1][3][0];
}

int past_the_first_dimension_of_a_cube(void)
{
    return cube[2][0][0];
}

void past_the_last_dimension_of_a_local_cube(void)
{
    int local[2][3][4];
    local[1][2][4] = 1;
}

int past_the_last_column_of_a_grid(void)
{
    return grid[2][4];
}

int past_the_last_row_of_a_grid(void)
{
    return grid[3][0];
}

void loop_one_past_the_last_dimension_of_a_cube(void)
{
    for (int k = 0; k <= 4; k++) {
        cube[1][2][k] = 0;
    }
}

int past_the_last_row_through_a_pointer_to_rows(void)
{
    int (*rows)[4] = grid;
    return rows[3][0];
}
