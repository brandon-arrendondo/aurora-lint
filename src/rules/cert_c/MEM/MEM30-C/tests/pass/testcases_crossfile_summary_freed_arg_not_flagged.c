/*
 * Rule: MEM30-C
 * Source: hostap ground-truth audit (task 159 wave 30) / task 396
 * Status: PASS - Should NOT trigger MEM30-C violation on 'hapd'
 *
 * Regression: mirrors hostap's ap_free_sta(hapd, sta), which frees the
 * SECOND argument (sta), not the first (hapd). Using 'hapd' after the call
 * is safe and must not be flagged as use-after-free.
 */

struct hostapd_data { int max_plinks; };
struct sta_info { int aid; };

static void ap_free_sta(struct hostapd_data *hapd, struct sta_info *sta)
{
	free(sta);
}

void caller(struct hostapd_data *hapd, struct sta_info *sta)
{
	ap_free_sta(hapd, sta);
	hapd->max_plinks = 1;
}
