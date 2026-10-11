/*
 * Rule: MSC37-C
 * Source: CERT MSC37-C text (C11 6.9.1p12) and the maintainer ruling on unreachable() and EX1
 * Status: FAIL - a function returning void * returns a value
 */

void *find(int key, void *table) {
  if (key > 0) {
    return table;
  }
}
