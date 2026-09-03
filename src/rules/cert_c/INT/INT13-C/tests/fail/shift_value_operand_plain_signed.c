/*
 * Rule: INT13-C
 * Source: run-229 audited-residue adjudication (task 754)
 * Status: FAIL - Should trigger INT13-C violation
 *
 * Guard rail: task 754 restricted shift checks to the LEFT (value) operand
 * and made variable-name resolution shift-count-aware. A plain signed
 * operand directly shifted must still be flagged -- "skip shifts entirely"
 * would have been the wrong fix.
 */

void shift_value_operand_plain_signed(void) {
    int val = 3;
    unsigned int result = val << 4;
}
