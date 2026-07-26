/*
 * Rule: MSC01-C
 * Source: wiki
 * Status: PASS - Compliant solution
 *
 * Fixture syntax corrected from the original scrape (source declaration was
 * truncated by a swallowed comment); control-flow logic unchanged from the
 * wiki example.
 */

#define ORIGINYEAR 1980

int IsLeapYear(int year);

void zune_fixed(unsigned int days) {
  int year = ORIGINYEAR;

  int daysThisYear = (IsLeapYear(year) ? 366 : 365);
  while (days > daysThisYear) {
    days -= daysThisYear;
    year += 1;
    daysThisYear = (IsLeapYear(year) ? 366 : 365);
  }
}
