/*
 * Rule: INT01-C
 * Source: task 1151 (fail-twin guard: ordinary identifiers that merely
 *   start with 'n' - node, name, new, null - must not be mistaken for the
 *   Hungarian n-prefixed size convention (nBytes, nNew, n2), which requires
 *   'n' followed by an uppercase letter or digit, or a short two-letter
 *   abbreviation)
 * Status: PASS - Should NOT trigger INT01-C violation
 */
#include <stddef.h>

struct node {
  int val;
};

void *node_alloc(struct node *node, size_t size);

void use(struct node *node) {
  void *p = node_alloc(node, sizeof(struct node));
  (void)p;
}
