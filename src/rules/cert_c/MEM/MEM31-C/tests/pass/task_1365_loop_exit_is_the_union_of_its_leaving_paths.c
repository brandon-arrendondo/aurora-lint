/*
 * Rule: MEM31-C
 * Source: hostap src/utils/os_internal.c and src/utils/os_unix.c
 *         os_rel2abs_path() (task 1365)
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * The retry idiom: allocate, try, and on failure free and go round again
 * with a bigger size; the `else` arm `break`s out with the buffer live,
 * and the free below the loop is the only free on that path. The body was
 * walked as one straight line into the code after the loop, so the arm
 * that frees and loops back read as reaching that free (a double free)
 * and the `if` as freeing in only one arm (a conditional leak). The code
 * after a loop is reached from the state before it, from every `break`
 * and `continue` in the body, and from the end of the body only when the
 * loop can end by its condition and the body's last statement does not
 * leave the function -- `for (;;)` and `while (1)` cannot. A `break`
 * inside a `switch` inside the loop ends the switch, not the loop. Two
 * more shapes the corpora surfaced: `p = alloc(); if (!p) break;` records
 * its exit on the arm where `p` holds nothing, so that record carries no
 * allocation; and `tmp = realloc(codes, n); ... codes = tmp;` inside the
 * body must keep the two names on one allocation site after the loop, or
 * the `free(codes)` below no longer credits `tmp`.
 */
#include <stdlib.h>
#include <errno.h>

char *getcwd(char *buf, size_t n);
void use(void *p);
int cond(void);

char *retry_until_it_fits(void)
{
	char *buf = NULL, *cwd;
	size_t len = 128;

	for (;;) {
		buf = malloc(len);
		if (buf == NULL)
			return NULL;
		cwd = getcwd(buf, len);
		if (cwd == NULL) {
			free(buf);
			if (errno != ERANGE) {
				return NULL;
			}
			len *= 2;
		} else {
			break;
		}
	}
	use(cwd);
	free(buf);
	return NULL;
}

char *retry_with_a_cap(void)
{
	char *buf = NULL, *cwd;
	size_t len = 128;
	int last_errno;

	while (1) {
		buf = malloc(len);
		if (buf == NULL)
			return NULL;
		cwd = getcwd(buf, len);
		if (cwd == NULL) {
			last_errno = errno;
			free(buf);
			if (last_errno != ERANGE)
				return NULL;
			len *= 2;
			if (len > 2000)
				return NULL;
		} else {
			buf[len - 1] = '\0';
			break;
		}
	}
	use(cwd);
	free(buf);
	return NULL;
}

void *get(int i);

void null_guard_then_break(void)
{
	void *p;

	for (int i = 0;; i++) {
		p = get(i);
		if (!p)
			break;
		use(p);
		free(p);
	}
}

int grown_buffer_freed_once_after_the_loop(int n)
{
	char *codes = malloc(8), *tmp;
	int count = 0, max = 8;

	if (!codes)
		return -1;
	while (n--) {
		codes[count++] = 1;
		if (count == max) {
			tmp = realloc(codes, (size_t)max * 2);
			if (!tmp) {
				free(codes);
				return -1;
			}
			codes = tmp;
			max *= 2;
		}
	}
	free(codes);
	return 0;
}

int break_inside_a_switch_inside_the_loop(void *p, int n, int t)
{
	while (n--) {
		switch (t) {
		case 1:
			free(p);
			break;
		default:
			break;
		}
		return 1;
	}
	free(p);
	return 0;
}

void body_that_returns_does_not_reach_the_code_after(void *p, int n)
{
	while (n--) {
		free(p);
		return;
	}
	free(p);
}
