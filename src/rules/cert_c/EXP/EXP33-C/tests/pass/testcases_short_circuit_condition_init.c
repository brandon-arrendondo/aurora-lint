/*
 * Rule: EXP33-C
 * Source: testcases (task 322)
 * Status: PASS - Should NOT trigger EXP33-C violation
 * Description: `value` is written via an output parameter in the FIRST
 * clause of a short-circuited `||`/`&&` condition, then read in the SECOND
 * clause of the SAME still-in-progress condition. The read-site query used
 * to have no "replay earlier clauses" path for if/while/for conditions
 * (only switch bodies had one), so it saw state as of the end of the
 * PRECEDING statement and missed the write from the first clause. Modeled
 * on hostap's src/eap_server/eap_server.c:2030 pattern
 * (`erp_parse_tlvs(pos, end, &parse, 1) < 0 || check_erp_tag(parse.keyname, ...)`).
 */

int parse_tlv(const char *pos, int *value);
int check_value(int value);
int use_value(int value);

int short_circuit_or_reads_earlier_write(const char *pos) {
    int value;

    if (parse_tlv(pos, &value) < 0 || check_value(value) < 0) {
        return -1;
    }
    return 0;
}

void short_circuit_and_reads_earlier_write(const char *pos) {
    int value;

    if (parse_tlv(pos, &value) == 0 && use_value(value)) {
        return;
    }
}
