/*
 * Rule: MEM31-C
 * Source: valkey src/config.c loadServerConfigFromString(), hostap
 *         wpa_supplicant/wpa_supplicant.c wpas_start_assoc_cb() (task 1339)
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * Two shapes that surfaced once a branch's fate was read off its last
 * statement. First: an `if` arm that allocates, frees and `continue`s, with
 * an `else` present. The else arm was walked on top of the true arm's
 * allocation records, so after the `if` the block the true arm had made
 * (and freed, in the arm that was discarded) read as live and was reported
 * leaked at every later exit. The else arm starts from the records before
 * the `if`, and the arm that reaches the code below is the one whose
 * records continue. Second: an `if`/`else if`/`else` chain split by
 * `#ifdef` around its middle arm parses with the `#endif` as the last
 * child of that arm's block, after its `return`; a directive is not a
 * statement, so it does not decide whether the arm falls through.
 *
 * And one that predates the task: when BOTH arms leave, the walk restored
 * the freed set from before the `if`, so a block both arms freed before
 * returning was reported never freed at the end of the function. Nothing
 * after such an `if` is reachable; the union of the arms' freed sets is
 * what continues.
 */
#include <stdlib.h>

int set(void *p);
int more(void);
int match(void);
int a(void);
int b(void);
int c(void);
void work(void);
void use(void *p);

int true_arm_continues_with_an_else_present(void)
{
	while (more()) {
		if (set(0)) {
			void *new_argv = malloc(8);

			if (!set(new_argv)) {
				free(new_argv);
				return -1;
			}
			free(new_argv);
			continue;
		} else {
			if (match())
				continue;
		}
		use(0);
	}
	return 0;
}

int else_arm_returns_and_the_true_arm_allocated(void)
{
	void *p;

	if (more()) {
		p = malloc(8);
	} else {
		return -1;
	}
	use(p);
	free(p);
	return 0;
}

int both_arms_allocate_and_neither_leaves(void)
{
	void *p;

	if (more()) {
		p = malloc(8);
	} else {
		p = calloc(1, 8);
	}
	use(p);
	free(p);
	return 0;
}

int both_arms_free_and_return(void)
{
	void *p = malloc(8);

	if (!p)
		return -1;
	if (more()) {
		free(p);
		return 1;
	} else {
		free(p);
		return 0;
	}
}

int true_arm_hands_over_else_arm_frees(void **out)
{
	void *p = malloc(8);

	if (!p)
		return -1;
	if (more()) {
		*out = p;
		return 0;
	} else {
		free(p);
		return -1;
	}
}

void chain_split_by_a_directive(void)
{
	void *ie = malloc(4);

	if (!ie)
		return;

	if (a()) {
		work();
#ifdef CONFIG_WPS
	} else if (b()) {
		free(ie);
		return;
#endif /* CONFIG_WPS */
	} else {
		work();
	}
	work();
	if (c()) {
		free(ie);
		return;
	}
	free(ie);
}
