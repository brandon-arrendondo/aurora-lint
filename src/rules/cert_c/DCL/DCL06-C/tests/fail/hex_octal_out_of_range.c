/*
 * Rule: DCL06-C
 * Source: task 1153 (fail-twin guard: normalizing hex/octal spellings of
 *   in-range values must not also accept out-of-range values written in
 *   hex or octal, e.g. sel4's src/plat/pc99/machine/pic.c:83, 0x0b/decimal
 *   11, confirmed TP in benchmark_adjudication/data/sel4/adjudication.csv)
 * Status: FAIL - Should trigger DCL06-C violation
 */

int compare_hex_out_of_range(int x) {
    if (x == 0x0b) {
        return 1;
    }
    return 0;
}

int compare_octal_out_of_range(int mode) {
    if (mode == 0777) {
        return 1;
    }
    return 0;
}
