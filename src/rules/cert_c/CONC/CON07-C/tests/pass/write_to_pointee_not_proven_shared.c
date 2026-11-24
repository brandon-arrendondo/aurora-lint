/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should not trigger CON07-C violation
 *
 * Subscripting a pointer writes what it points at, not the shared object
 * holding the pointer: a pointer member's pointee and a shared pointer that
 * is never given an address are not proven to be shared storage. A plain
 * store to one member is not a compound operation.
 */

struct buffer {
  int n;
  char *data;
};

static struct buffer out;
static char *scratch;

void fill(int i) { out.data[i]++; }

void poke(int i) { scratch[i] += 2; }

void reset(void) { out.n = 4; }
