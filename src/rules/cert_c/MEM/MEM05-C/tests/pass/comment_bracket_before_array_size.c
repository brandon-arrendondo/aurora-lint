/* A `]` inside a comment before the array declarator must not reverse the size slice. */
void f(void) { int arr /* ] */ [] = {1, 2, 3}; (void)arr; }
