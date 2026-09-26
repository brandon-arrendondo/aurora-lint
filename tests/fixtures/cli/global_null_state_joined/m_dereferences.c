/*
 * EXP34-C through an extern global whose null state comes from other files.
 * a_defines_null.c initializes g to NULL and z_assigns_buffer.c assigns it a
 * buffer, so here g may be null: the states from both files are joined.
 */
extern char *g;

void use(void) {
    *g = 1;
}
