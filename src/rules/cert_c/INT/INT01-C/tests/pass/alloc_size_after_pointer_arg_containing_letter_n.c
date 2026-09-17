/*
 * Rule: INT01-C
 * Source: task 1151 (fail-twin guard for
 *   alloc_size_after_pointer_arg_containing_letter_n.c: a pointer/handle
 *   argument that merely contains the letter 'n' must not be misattributed
 *   as a size argument when the call has no other, genuinely non-size_t
 *   size argument)
 * Status: PASS - Should NOT trigger INT01-C violation
 */
#include <stddef.h>

struct connection {
  int fd;
};

void *conn_alloc(struct connection *connection, size_t nbytes);

void use(struct connection *connection) {
  void *buf = conn_alloc(connection, sizeof(int));
  (void)buf;
}
