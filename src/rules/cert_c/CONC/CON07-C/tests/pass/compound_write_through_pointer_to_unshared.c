/*
 * Rule: CON07-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON07-C violation
 *
 * Compound operations through a pointer are judged by what the pointer
 * points at. None of these is known to point at a shared object: one points
 * at a thread-local array, one is a parameter, one is retargeted to an
 * object the caller supplies, and one points at a local array. Moving a
 * thread-local pointer along a shared array writes only the pointer. A
 * subscript of a shared pointer, or a pointer to an array read as the
 * array, reaches an object the pointer points at, not the shared object
 * itself. A retarget in parentheses, inside a macro, or by a macro the
 * pointer is passed to still retargets, and a pointer with external
 * linkage may be retargeted by another file.
 */

static _Thread_local int tl_buf[4];
static _Thread_local int *tl_cursor = tl_buf;

void step_local(void) { (*tl_cursor)++; }

void through_param(int *p) { (*p)++; }

static int shared[4];
static _Thread_local int *moved = shared;

void retarget(int *other) { moved = other; }

void step_moved(void) { (*moved)++; }

void own(void) {
  int local[2] = {0, 0};
  int *q = local;
  q[0] += 1;
}

static int walk_buf[4];
static _Thread_local int *walker = walk_buf;

void advance(void) { walker += 1; }

static char *g_buf;

void through_pointer_subscript(void) {
  char *p = &g_buf[3];
  (*p)++;
}

static int (*parr)[4];

void through_pointer_to_array(void) {
  int *q = (int *)parr;
  (*q)++;
}

static int paren_shared[4];

void paren_retarget(void) {
  int local = 0;
  int *p = paren_shared;
  (p) = &local;
  (*p)++;
}

static int macro_shared[4];
static _Thread_local int macro_tl[4];
#define RETARGET() (mp = macro_tl)

void macro_retarget(void) {
  int *mp = macro_shared;
  RETARGET();
  (*mp)++;
}

static int ext_shared[4];
int *ext_cursor = ext_shared;

void through_external_pointer(void) { (*ext_cursor)++; }

static int arg_shared[4];
static _Thread_local int arg_tl[4];
static int *arg_cursor = arg_shared;
#define SET(x, v) ((x) = (v))

void macro_argument_retarget(void) {
  SET(arg_cursor, arg_tl);
  (*arg_cursor)++;
}
