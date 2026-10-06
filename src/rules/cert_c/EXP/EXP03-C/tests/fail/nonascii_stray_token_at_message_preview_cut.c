/* Malformed: non-ASCII text sits where a token belongs. */
#include <stdlib.h>
struct record { int id; double value; char name[32]; };
void f(void) {
  struct record *dst = (struct record *)malloc(
      sizeof(int) + éééééééééééééééééééééééééééééé sizeof(double) + 32 * sizeof(char));
  free(dst);
}
