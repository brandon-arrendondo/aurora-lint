/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger CON07-C violation
 *
 * A const object is never written, so no other thread can change it
 * between two reads: combining reads of const lookup tables, or of a const
 * object and one shared variable read once, is not a compound operation on
 * shared state. Constness is the object's own, per declarator: through a
 * typedef, on the pointer itself (`*const`), or in a declaration that also
 * declares writable objects.
 */

typedef const int cint;

static const int table[4] = {1, 2, 3, 4}, other[4] = {5, 6, 7, 8};
int const limits[2] = {16, 32};
static cint low[2] = {0, 1}, high[2] = {2, 3};
static char *const first = 0, *const last = 0;
static const int base = 10, *cursor = 0;
static int level;

int lookup(int a) { return table[a] + other[a]; }

int bounded(int a) { return table[a] * limits[a & 1]; }

int span(int i) { return high[i] - low[i]; }

long extent(void) { return last - first; }

int scaled(void) { return level * base; }
