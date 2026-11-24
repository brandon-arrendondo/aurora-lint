/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=7
 *
 * A compound operation on a member or an element of a shared object is a
 * compound operation on that object: a structure's member, an array
 * element's member, a two-dimensional element, an element of an array of a
 * typedef'd row type. Arrays and pointers declared without an initializer
 * are shared objects too.
 */

struct stats {
  int n;
  int flags;
  int x;
};

typedef int row_t[4];

static struct stats g;
static struct stats slots[8];
static int a[4], b[4];
static char *cursor;
static int grid[3][3];
static row_t rows[3];

void count(void) { g.n++; }

void mark(void) { g.flags |= 4; }

void bump_slot(int j) { slots[j].x++; }

void add_rows(int i) { a[i] += b[i]; }

void advance(void) { cursor++; }

void step_cell(int i, int j) { grid[i][j] = grid[i][j] + 1; }

void bump_row(void) { rows[1][2]++; }
