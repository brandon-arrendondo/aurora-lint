/*
 * Rule: MSC01-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC01-C violation
 */

#define ORIGINYEAR 1980
UINT32 days = /* Number of days since January 1, 1980 */
int year = ORIGINYEAR;
/* ... */

while (days > 365) {
  if (IsLeapYear(year)) {
    if (days > 366) {
      days -= 366;
      year += 1;
    }
  }
  else {
    days -= 365;
    year += 1;
  }
}