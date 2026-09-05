/*
 * Rule: MEM30-C
 * Source: hostap ground-truth audit (task 159 wave 30) / task 396
 * Status: FAIL - Should trigger MEM30-C violation on 'sta', NOT 'hapd'
 *
 * Regression: mirrors hostap's ap_free_sta(hapd, sta), which frees the
 * SECOND argument (sta), not the first (hapd). MEM30-C's cross-file
 * FunctionSummary (frees_params) must attribute the free to the correct
 * parameter position instead of assuming a fixed "first" or "last" slot
 * from the callee's name alone.
 */

#include <stdio.h>

struct hostapd_data { int max_plinks; };
struct sta_info { int aid; };

static void ap_free_sta(struct hostapd_data *hapd, struct sta_info *sta)
{
	free(sta);
}

void caller(struct hostapd_data *hapd, struct sta_info *sta)
{
	ap_free_sta(hapd, sta);
	printf("%d\n", sta->aid);
}
