/*
 * Rule: MEM05-C
 * Source: custom
 * Status: FAIL - Should trigger MEM05-C violation
 * Description: sizeof of a variable-length array type is evaluated at run
 * time and is not an integer constant expression, so each array sized by
 * one is itself a VLA: a type operand with a runtime size, an element of a
 * VLA of VLAs, a dereferenced pointer to a VLA, an object of a VLA typedef,
 * a typedef of that typedef, and an array sized by another such array.
 */
void sized_by_runtime_types(int n) {
    int by_type[sizeof(int[n])];
    int grid[n][n];
    int by_row[sizeof(grid[0])];
    int by_deref[sizeof(*grid)];
    int (*row)[n] = 0;
    int by_pointee[sizeof *row];
    typedef int vt[n];
    vt x;
    int by_typedef_object[sizeof x];
    int by_typedef[sizeof(vt)];
    typedef vt vt2;
    int by_typedef_chain[sizeof(vt2)];
    int by_vla[(sizeof by_typedef_object)];
    (void)by_type; (void)by_row; (void)by_deref; (void)by_pointee;
    (void)by_typedef_object; (void)by_typedef; (void)by_typedef_chain;
    (void)by_vla;
}
