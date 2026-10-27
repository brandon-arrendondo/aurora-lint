/*
 * Rule: DCL37-C
 * Status: FAIL - C 7.1.3 reserves every name beginning with an underscore at
 * file scope in the tag name space as well as the ordinary one. A tag is
 * declared by a specifier with a body or by one standing alone.
 * Expect: count=3
 */

struct _node { /* Expect: here */
  struct _node *next;
};

union _cell; /* Expect: here */

enum _colour { red, green }; /* Expect: here */

/* Naming the tag again declares nothing. */
typedef struct _node node_t;
