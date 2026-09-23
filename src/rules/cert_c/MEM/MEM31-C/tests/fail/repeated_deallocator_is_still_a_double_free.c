/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The guard on an earlier fix's relaxation. Only a SECOND, DIFFERENT
 * deallocator name is the teardown-pair idiom; repeating ONE name is the
 * shape the load-bearing single-argument fallback exists to catch, and it
 * still reports. So does a literal `free()` twice, and so does a repeat that
 * follows a reallocation -- a rebind drops the guessed mark rather than
 * carrying it past the fresh block.
 */

#include <stdlib.h>

struct obj;
extern struct obj *obj_new(void);
extern void sqlite3_free(struct obj *p);
extern void obj_close(struct obj *p);

void repeated_external_deallocator(void) {
    struct obj *p = obj_new();
    sqlite3_free(p);
    sqlite3_free(p);
}

void repeated_literal_free(void) {
    char *p = malloc(16);
    free(p);
    free(p);
}

void repeat_after_a_rebind(void) {
    struct obj *p = obj_new();
    obj_close(p);
    p = obj_new();
    sqlite3_free(p);
    sqlite3_free(p);
}
