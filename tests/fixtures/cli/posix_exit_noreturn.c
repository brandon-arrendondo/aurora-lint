#include <unistd.h>
int f(int x) {
  if (x > 0) {
    return 1;
  }
  _exit(2);
}
