/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
 * Status: PASS - the last arm jumps back to a label above the switch
 */

extern int convert(int *state);

int prepare(int state, int tries) {
retry:
  switch (state) {
    case 0:
      return 0;
    default: {
      tries -= convert(&state);
      goto retry;
    }
  }
}
