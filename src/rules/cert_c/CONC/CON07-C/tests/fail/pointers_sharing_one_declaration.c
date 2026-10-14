/*
 * Rule: CON07-C
 * Source: testcases
 * Status: FAIL - Should trigger CON07-C violation
 *
 * One declaration declares two pointers, one into a shared array and one
 * into a thread-local array. Each is judged by what it points at, whichever
 * is written through first: the write through the thread-local one comes
 * first here and is not reported, and the write through the shared one
 * still is.
 */

static int g_arr[4];
static _Thread_local int tls_arr[4];
static int *p = g_arr, *q = tls_arr;

void through_q(void) { (*q)++; }

void through_p(void) { (*p)++; }
