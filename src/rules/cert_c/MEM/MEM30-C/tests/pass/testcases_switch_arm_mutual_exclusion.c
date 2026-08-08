/*
 * Rule: MEM30-C
 * Source: hostap ground-truth audit (task 159 waves 30/33) / task 398
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * Regression: mirrors hostap's mesh_mpm_fsm switch(event) pattern. A free
 * in one `case` arm (with `break`) must not poison a later, mutually
 * exclusive arm's use of the same variable -- only one arm executes per
 * call, never both.
 */

#include <stdlib.h>
#include <stdio.h>

struct sta_info { int aid; };

void mesh_mpm_fsm(struct sta_info *sta, int event)
{
	switch (event) {
	case 1:
		free(sta);
		break;
	case 2:
		printf("%d\n", sta->aid);
		break;
	default:
		break;
	}
}
