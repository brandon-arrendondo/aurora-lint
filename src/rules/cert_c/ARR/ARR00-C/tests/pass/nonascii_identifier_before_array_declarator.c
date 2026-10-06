/* A non-ASCII identifier within 50 bytes before an array declarator must not panic the declaration look-back. */
int main() {
  int éééééééééééééééééééééééééééééé,  buffer[10];
  for (int i = 0; i <= 10; i++) {
    buffer[i] = i;
  }
  return 0;
}
