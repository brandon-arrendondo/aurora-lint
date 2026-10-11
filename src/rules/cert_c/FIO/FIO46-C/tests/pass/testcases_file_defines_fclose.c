/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - the file defines its own fclose, so a call to it is not
 * the library's and closes no FILE
 */

struct handle {
  int fd;
  int open;
};

void use(struct handle *h);

int fclose(struct handle *h) {
  h->open = 0;
  return 0;
}

void f(struct handle *h) {
  fclose(h);
  use(h);
  fclose(h);
}
