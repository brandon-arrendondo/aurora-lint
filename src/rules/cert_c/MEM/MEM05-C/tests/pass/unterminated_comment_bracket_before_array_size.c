/* Malformed: the comment holding the `]` is never closed. */
void f(void) { int arr /* ] 
 [] = {1, 2, 3}; (void)arr; }
