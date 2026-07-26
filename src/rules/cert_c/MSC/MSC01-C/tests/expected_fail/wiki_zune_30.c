/*
 * Rule: MSC01-C
 * Source: wiki
 * Status: EXPECTED FAIL - Known limitation: MSC01-C does not detect this
 * pattern (a nested if with no else, whose missing branch skips a state
 * mutation the enclosing loop depends on to terminate -- the real Zune 30
 * "leap day" bug). Detecting it in general requires data-flow reasoning
 * about which branches update a loop's controlling variables, which is out
 * of scope for a purely structural if/else-if-chain and switch-default
 * check; a generic "nested if without else" rule would be extremely noisy
 * on ordinary, correct code. Fixture syntax corrected from the original
 * scrape (source declaration was truncated by a swallowed comment) but the
 * control-flow logic is unchanged from the wiki example.
 */

#define ORIGINYEAR 1980

int IsLeapYear(int year);

void zune_bug(unsigned int days) {
  int year = ORIGINYEAR;

  while (days > 365) {
    if (IsLeapYear(year)) {
      if (days > 366) {
        days -= 366;
        year += 1;
      }
    } else {
      days -= 365;
      year += 1;
    }
  }
}
