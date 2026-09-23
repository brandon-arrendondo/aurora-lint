/*
 * Rule: DCL06-C
 * Source: real-world, mirroring sel4's src/plat/pc99/machine/io.c and pic.c,
 *   raylib's src/rmodels.c, and mosquitto's src/net.c (benchmark_adjudication
 *   data/{sel4,raylib,mosquitto}/adjudication.csv, "hex/octal bug: literal
 *   is decimal N (0-10 range) but its exact spelling is not normalized")
 * Status: PASS - a small in-range value written in hex or octal is just as
 *   acceptable as the same value written in decimal
 * Description: is_acceptable_integer() only recognized "0x0"/"0x1"/"0x2" as
 *   accepted hex spellings and never normalized octal at all, so e.g. 0x7
 *   (decimal 7) or 0007 (decimal 7) was flagged as a magic number purely
 *   because of how it was spelled, even though "7" itself is accepted.
 */

int compare_hex(int x) {
    if (x == 0x7) {
        return 1;
    }
    if (x == 0x06) {
        return 1;
    }
    if (x == 0x0a) {
        return 1;
    }
    return 0;
}

int compare_octal(int mode) {
    if (mode == 0007) {
        return 1;
    }
    return 0;
}
