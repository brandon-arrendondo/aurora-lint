/*
 * Rule: DCL36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL36-C violation
 *
 * Every pair below gives its identifier one linkage (C23 6.2.2 p3-p5).
 * `extern` takes the linkage of a visible prior declaration (p4), and a
 * function with no storage-class specifier is read as if `extern` (p5), so
 * neither can disagree with the declaration before it. `inline` and
 * `_Thread_local` are not about linkage at all.
 */

/* extern, then a plain object: both external. */
extern int shared_count;
int shared_count;

/* A plain object, then extern: extern takes the prior's linkage. */
int shared_mode;
extern int shared_mode;

/* static, then extern: extern takes the prior's (internal) linkage. */
static int hidden_level;
extern int hidden_level;

/* static, then a plain function: the function inherits internal linkage. */
static int helper(int x);
int helper(int x);

/* static, then a plain prototype returning a pointer. */
static char *name_of(int id);
char *name_of(int id);

/* inline, then a plain prototype: inline names no linkage. */
inline int twice(int x);
int twice(int x);

/* _Thread_local, then a plain declaration: both external. */
_Thread_local int per_thread;
int per_thread;

int main(void) {
    return shared_count + shared_mode + hidden_level + helper(1) + twice(per_thread) + (name_of(0) != 0);
}
