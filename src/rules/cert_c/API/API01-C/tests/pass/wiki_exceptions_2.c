/*
 * Rule: API01-C
 * Source: wiki
 * Status: PASS - API01-C-EX1: struct used only as a fixed-size array, not
 * individually malloc'd/linked nodes, so the string-before-pointer layout
 * is permitted.
 */

const size_t String_Size = 20;
struct node_s {
  char name[String_Size];
  struct node_s* next;
};
struct node_s list[10];