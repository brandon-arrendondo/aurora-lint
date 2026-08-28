/*
 * Rule: MEM30-C
 * Source: regression counterpart to testcases_field_reassign_nonalloc_call.c
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * Unlike the pass fixture, only ONE branch reassigns the field; the other
 * leaves it freed and falls through to the same read -- a genuine
 * use-after-free that the field-reassignment fix must not mask.
 */

#include <stdlib.h>

struct data { char *next_pseudonym; };

extern void wpa_printf(int level, const char *fmt, ...);

void rebuild(struct data *data, int cond1)
{
	free(data->next_pseudonym);
	if (cond1) {
		data->next_pseudonym = 0;
	}

	wpa_printf(0, "%s", data->next_pseudonym);
}
