/* Malformed: the subscript of a string literal holding a `]` is never closed. */
char f(void) { return "a]b"[0; }
