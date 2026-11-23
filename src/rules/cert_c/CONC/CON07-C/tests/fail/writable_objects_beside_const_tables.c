/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=3
 *
 * The const tables are only read, but each function still operates on
 * shared objects that can be written: a counter incremented by a value read
 * from a table, two writable pointers to const (`const char *` is a
 * pointer that can be retargeted, whatever it points at), and a writable
 * pointer declared beside a const object in one declaration.
 */

typedef const char *label_t;

static const int weights[4] = {1, 2, 3, 4};
static int total;
static label_t head = 0, tail = 0;
static const int seed = 7, *pick = 0, *alt = 0;

void accumulate(int a) { total += weights[a]; }

void relabel(void) {
  head = "a";
  tail = "b";
}

void repoint(void) {
  pick = &seed;
  alt = &seed;
}
