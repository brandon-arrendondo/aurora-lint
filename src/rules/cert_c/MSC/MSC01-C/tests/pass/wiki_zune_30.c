/*
 * Rule: MSC01-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#define ORIGINYEAR 1980
UINT32 days = /* Input parameter */
int year = ORIGINYEAR;
/* ... */

int daysThisYear = (IsLeapYear(year) ? 366 : 365);
while (days > daysThisYear) {
  days -= daysThisYear;
  year += 1;
  daysThisYear = (IsLeapYear(year) ? 366 : 365);
}