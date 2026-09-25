/*
 * Rule: FIO05-C
 * Source: regression (Juliet CWE773 fopen_12 shape)
 * Status: PASS - Should NOT trigger FIO05-C violation
 *
 * One handle holds two files in turn, and the second file is opened once in
 * each arm of an if/else. No execution opens "second.txt", closes it, and
 * opens it again: the two opens are in opposite arms. The else arm's first
 * fclose closes "first.txt", the only open that reaches it. The close used
 * to be filed under whichever filename a HashMap listed first, so this
 * reported a reopen at the else arm's fopen on some runs and not others.
 */

int choose(void);

void opposite_arms(void) {
  FILE *data = fopen("first.txt", "w+");
  if (choose()) {
    if (data != NULL) {
      fclose(data);
    }
    data = fopen("second.txt", "w+");
    if (data != NULL) {
      fclose(data);
    }
  } else {
    if (data != NULL) {
      fclose(data);
    }
    data = fopen("second.txt", "w+");
    if (data != NULL) {
      fclose(data);
    }
  }
}
