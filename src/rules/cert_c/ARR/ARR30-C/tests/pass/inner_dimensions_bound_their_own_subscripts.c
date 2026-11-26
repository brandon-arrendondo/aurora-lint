/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Every subscript is within the dimension it indexes
 *
 * Each subscript of a multidimensional array is bounded by its own
 * dimension: in `int cube[2][3][4]` the last index runs to 3, the middle
 * one to 2 and the first to 1. A pointer to an array, `int (*rows)[4]`, is
 * no array of four elements: its first subscript steps over whole rows,
 * and nothing declares how many there are.
 */
int cube[2][3][4];
int grid[3][4];

int last_element_of_a_cube(void)
{
    return cube[1][2][3];
}

int last_row_of_a_cube(void)
{
    return cube[1][2][0];
}

void last_dimension_of_a_cube_by_a_loop(void)
{
    for (int k = 0; k < 4; k++) {
        cube[1][2][k] = 0;
    }
}

void middle_dimension_of_a_cube_by_a_loop(void)
{
    for (int j = 0; j < 3; j++) {
        cube[0][j][0] = 0;
    }
}

int last_element_of_a_local_cube(void)
{
    int local[2][3][4] = {{{0}}};
    local[1][2][3] = 1;
    return local[0][0][0];
}

int last_element_of_a_grid(void)
{
    return grid[2][3];
}

void last_column_of_a_grid_by_a_loop(void)
{
    for (int k = 0; k < 4; k++) {
        grid[2][k] = 0;
    }
}

int (*rows_from_elsewhere(void))[4];

int row_past_the_fourth_through_a_pointer_to_rows(void)
{
    int (*rows)[4] = rows_from_elsewhere();
    return rows[5][3];
}

int (*planes_from_elsewhere(void))[3][4];

int last_element_through_a_pointer_to_planes(void)
{
    int (*planes)[3][4] = planes_from_elsewhere();
    return planes[6][2][3];
}
