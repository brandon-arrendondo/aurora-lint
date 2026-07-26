/*
 * Rule: MSC20-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

int f(int i) {
  int j=0;
  switch (i) {
    case 1:
      /* No break; process case 2 as well */
    case 2:
      j++;
      /* No break; process case 3 as well */
    case 3:
      j++;
      break;
    default:
      /* Default action */
      return j;
  }
  for(j++;j<10;j++) {
    j+=2;
  }
  return j;
}