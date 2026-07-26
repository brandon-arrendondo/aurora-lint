/*
 * Rule: MSC20-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC20-C violation
 */

int f(int i) {
  int j=0;
  switch (i) {
    case 1:
      for(j=0;j<10;j++) {
      /* No break; process case 2 as well */
    case 2: /* switch jumps inside the for block */
        j++;
      /* No break; process case 3 as well */
    case 3:
        j++;
      }
      break;
  default:
    /* Default action */
    break;
  }
  return j;
}