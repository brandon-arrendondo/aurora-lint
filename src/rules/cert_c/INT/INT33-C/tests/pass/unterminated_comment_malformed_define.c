/* The malformed #define sits inside an unterminated comment that also holds non-ASCII text. The macro scan is textual, so it still reads the line. */

/* unterminated comment with é
#define BAD) (a) / (b)

int main(void) { return 0; }
