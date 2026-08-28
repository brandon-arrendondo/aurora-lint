/*
 * Rule: MEM30-C
 * Source: hostap ground-truth audit (task 544/563)
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * Regression: mirrors hostap's eap_aka_build_encr, which frees a struct
 * field then reassigns it in every arm of an if/else-if/else chain. Two of
 * the three arms assign a literal NULL (always clears the freed state), but
 * the middle arm assigns the result of an arbitrary project function
 * (eap_sim_db_get_next_pseudonym) whose name doesn't match the
 * `is_fresh_allocation_name` heuristic (no ALLOC/STRDUP/STRNDUP/MEMDUP
 * substring). A plain-identifier LHS clears freed state on ANY non-NULL
 * reassignment regardless of the RHS call's name, but a field-expression
 * LHS only did so when the name heuristic matched -- leaving the field
 * permanently marked freed after this one arm and false-flagging every
 * later read.
 */

#include <stdlib.h>

struct data { char *next_pseudonym; };

extern char *eap_sim_db_get_next_pseudonym(int priv);
extern void wpa_printf(int level, const char *fmt, ...);

void rebuild(struct data *data, int cond1, int cond2)
{
	free(data->next_pseudonym);
	if (cond1) {
		data->next_pseudonym = NULL;
	} else if (cond2) {
		data->next_pseudonym = eap_sim_db_get_next_pseudonym(1);
	} else {
		data->next_pseudonym = NULL;
	}

	if (data->next_pseudonym)
		wpa_printf(0, "%s", data->next_pseudonym);
}
