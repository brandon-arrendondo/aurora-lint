/*
 * Rule: INT14-C
 * Source: hostap real-world audit (task 462, batch 16-40_b18)
 * Status: PASS - A call_expression's callee identifier must not be
 *   collected as a "variable" for the mixed bitwise/arithmetic check
 *
 * Before this fix, extract_variables() collected every identifier node
 * in a binary_expression's subtree, including a called function's own
 * name -- so `(le_to_host16(0x1234) & 0x7fff) * 8` recorded a bitwise
 * op (from the outer `&` node's subtree) AND an arithmetic op (from
 * the outer `*` node's subtree, which contains the `&` node) for the
 * identifier `le_to_host16` itself, misattributing the finding to the
 * function/macro name instead of any real data variable. Real example:
 * hostap's wmm.c:251, `duration = (le_to_host16(tspec->nominal_msdu_size)
 * & 0x7fff) * 8 / (...) + 50;` -- flagged 'le_to_host16', not a
 * variable at all, as having "both bitwise and arithmetic operations".
 * (The call's argument is a literal here, not an identifier, so this
 * fixture isolates the callee-name bug from the separate, already-
 * documented "same identifier reused across nested binary_expression
 * subtrees" member-conflation family, which still needs its own fix.)
 */

unsigned short le_to_host16(unsigned short v);

int compute_duration(void) {
	int duration = (le_to_host16(0x1234) & 0x7fff) * 8;
	return duration;
}
