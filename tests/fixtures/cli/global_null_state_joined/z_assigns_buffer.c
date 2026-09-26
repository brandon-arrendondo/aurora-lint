/*
 * Assigns g a non-null buffer. Named to sort last, so a last-file-wins merge
 * would keep only this state and hide a_defines_null.c's NULL.
 */
char *g;
static char buf[4];

void init(void) {
    g = buf;
}
