/*
 * Rule: INT14-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

int value = /* Interesting value */
unsigned char bytes[sizeof(int)];
for (int i = 0; i < sizeof(int); i++) {
  bytes[i] = value >> (i*8) & 0xFF;
}
/* bytes[] now has same bit representation as value  */