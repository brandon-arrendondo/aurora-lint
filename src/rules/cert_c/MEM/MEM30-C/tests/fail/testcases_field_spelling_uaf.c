/*
 * Rule: MEM30-C
 * Source: task 1 (field-sensitive alias/points-to infrastructure)
 * Status: FAIL - Should trigger MEM30-C violation
 * Reason: free(p->buf) followed by an access through a DIFFERENT spelling
 * of the same field, (*p).buf, must still be recognized as the same
 * storage location and flagged as use-after-free.
 */

#include <stdlib.h>

struct s {
    char *buf;
};

void use(char *c);

void field_spelling_uaf(struct s *p) {
    free(p->buf);
    use((*p).buf);
}
