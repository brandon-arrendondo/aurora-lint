/*
 * Rule: MEM30-C
 * Source: hostap ground-truth audit (task 159 waves 30/33) / task 398
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * Regression: a free in ANY switch arm (even with `break`) means the
 * pointer may be freed by the time control reaches the code AFTER the
 * switch -- unlike a free-then-use in a DIFFERENT, mutually exclusive arm
 * (which must NOT be flagged, see testcases_switch_arm_mutual_exclusion.c),
 * a use after the whole switch statement is a genuine potential UAF.
 */

#include <stdlib.h>
#include <stdio.h>

struct sta_info { int aid; };

void caller(struct sta_info *sta, int event)
{
	switch (event) {
	case 1:
		free(sta);
		break;
	default:
		break;
	}

	printf("%d\n", sta->aid);
}
