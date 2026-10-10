/* A `]` inside a string literal that is subscripted must not reverse the index slice. */
char f(void) { return "a]b"[0]; }
