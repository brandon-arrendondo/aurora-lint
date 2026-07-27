/*
 * Rule: API01-C
 * Status: PASS - API01-C-EX1: struct defined and declared as a fixed-size
 * array in a single statement (`struct node_s { ... } list[10];`), not
 * individually malloc'd/linked nodes.
 */

const size_t String_Size = 20;
struct node_s {
  char name[String_Size];
  struct node_s* next;
} list[10];
