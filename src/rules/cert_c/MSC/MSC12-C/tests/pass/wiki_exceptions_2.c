/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

typedef enum { Red, Green, Blue } Color;
const char* f(Color c) {
  switch (c) {
    case Red: return "Red";
    case Green: return "Green";
    case Blue: return "Blue";
    default: return "Unknown color";   /* Not dead code */
  }
}

void g() {
  Color unknown = (Color)123;
  puts(f(unknown));
}