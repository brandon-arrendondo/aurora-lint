/*
 * Rule: DCL13-C
 * Source: synthetic
 * Status: PASS - Should not trigger DCL13-C violation
 *
 * A parameter is judged by what the function does with what it points
 * to, never by its name. `readfds` here is written through, as `select`
 * writes its fd sets, so neither the prototype nor the definition can
 * take `const`. A prototype on its own, such as a library function's,
 * says nothing about the pointee and is never reported.
 */

#include <stddef.h>

struct fd_bits {
  unsigned long bits[16];
};

int wait_ready(int nfds, struct fd_bits *readfds, struct fd_bits *writefds);

int select_like(int nfds, struct fd_bits *readfds, struct fd_bits *writefds,
                struct fd_bits *exceptfds, void *timeout);

void log_read_data(char *read_buffer);

int wait_ready(int nfds, struct fd_bits *readfds, struct fd_bits *writefds) {
  readfds->bits[0] = 0;
  writefds->bits[0] = (unsigned long)nfds;
  return nfds;
}
