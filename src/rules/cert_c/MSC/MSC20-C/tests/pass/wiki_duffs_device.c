/*
 * Rule: MSC20-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

int n = (count + 7) / 8;
switch (count % 8) {
  case 0: *to = *from++; /* Fall through */
  case 7: *to = *from++; /* Fall through */
  case 6: *to = *from++; /* Fall through */
  case 5: *to = *from++; /* Fall through */
  case 4: *to = *from++; /* Fall through */
  case 3: *to = *from++; /* Fall through */
  case 2: *to = *from++; /* Fall through */
  case 1: *to = *from++; /* Fall through */
}
while (--n > 0) {
  *to = *from++;
  *to = *from++;
  *to = *from++;
  *to = *from++;
  *to = *from++;
  *to = *from++;
  *to = *from++;
  *to = *from++;
}