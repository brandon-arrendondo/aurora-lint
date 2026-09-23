/*
 * Rule: MEM30-C
 * Source: valkey src/acl.c ACLUserCheckModuleCommandPerm(), src/sds.c
 *         sdscatvprintf()
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * A loop body was walked as one straight line into the code after the
 * loop, so a body that frees and then `return`s handed the freed state to
 * the statement after the loop, which only the body's `continue`s and
 * the zero-iteration path reach. The code after a loop is reached from
 * the state before it, from every `break` and `continue` in the body, and
 * from the end of the body when its last statement does not leave the
 * function. A `break` inside a `switch` inside the loop ends the switch,
 * not the loop. And on the arm of `if (buf != staticbuf)`, `buf` is not
 * `staticbuf`, whatever `char *buf = staticbuf;` recorded: freeing one
 * there does not free the other.
 */
#include <stdlib.h>

int more(void);
int fits(char *buf, size_t n);
void use(void *p);

int frees_then_returns_inside_the_loop(int n)
{
	for (int i = 0; i < n; i++) {
		void *argv = malloc(8);

		if (!argv)
			continue;
		for (int j = 0; j < n; j++) {
			if (j == 3)
				continue;
			use(argv);
			free(argv);
			return 1;
		}
		free(argv);
	}
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
	use(p);
	return 0;
}

void do_while_body_returns(void *p)
{
	do {
		free(p);
		return;
	} while (0);
	use(p);
}

void *grow_until_it_fits(void *s, int big)
{
	char staticbuf[64];
	char *buf = staticbuf;
	size_t buflen = sizeof(staticbuf);
	int len;

	if (big) {
		buf = malloc(1024);
		if (buf == NULL)
			return NULL;
		buflen = 1024;
	}
	while (1) {
		len = fits(buf, buflen);
		if (len < 0) {
			if (buf != staticbuf)
				free(buf);
			return NULL;
		}
		if ((size_t)len >= buflen) {
			if (buf != staticbuf)
				free(buf);
			buflen = (size_t)len + 1;
			buf = malloc(buflen);
			if (buf == NULL)
				return NULL;
			continue;
		}
		break;
	}
	use(buf);
	if (buf != staticbuf)
		free(buf);
	return s;
}
