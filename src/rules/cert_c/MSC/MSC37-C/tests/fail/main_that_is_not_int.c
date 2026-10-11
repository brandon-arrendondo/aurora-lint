/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
 * Status: FAIL - EX1 is for int main
 */

extern int puts(const char *s);

long main(void) {
  puts("started");
}
