/*
 * Rule: MEM30-C
 * Source: hostap ground-truth audit (task 159 wave 30) / task 396
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * Regression: hostap's plink_free_count(hapd) is a pure counter (no free at
 * all), but its name contains "FREE" so MEM30-C's name-based fallback
 * heuristic misidentified it as a free() call and flagged the argument as
 * freed. When a cross-file FunctionSummary is available showing the callee
 * frees nothing, it must override the name heuristic.
 */

struct hostapd_data { int max_plinks; int num_plinks; };

static int plink_free_count(struct hostapd_data *hapd)
{
	if (hapd->max_plinks > hapd->num_plinks)
		return hapd->max_plinks - hapd->num_plinks;
	return 0;
}

void caller(struct hostapd_data *hapd)
{
	if (plink_free_count(hapd) == 0) {
		hapd->max_plinks = 1;
	}
}
