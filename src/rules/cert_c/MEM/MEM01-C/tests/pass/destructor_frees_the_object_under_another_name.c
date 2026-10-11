/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
 * Status: PASS - the object is freed next through the pointer it was cast from
 */

#include <stdlib.h>

struct base {
  int kind;
};

struct table {
  struct base base;
  char *db;
  char *name;
};

int disconnect(struct base *vtab) {
  struct table *tab = (struct table *)vtab;
  free(tab->db);
  free(tab->name);
  free(vtab);
  return 0;
}
