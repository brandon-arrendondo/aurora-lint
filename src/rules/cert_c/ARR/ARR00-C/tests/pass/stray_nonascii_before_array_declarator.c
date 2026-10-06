/* Malformed: non-ASCII text sits where a declarator belongs. */
int main() {
  int éééééééééééééééééééééééééééééé =,  buffer[10];
  for (int i = 0; i <= 10; i++) {
    buffer[i] = i;
  }
  return 0;
}
