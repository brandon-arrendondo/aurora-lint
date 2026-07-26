/*
 * Rule: API01-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

const size_t String_Size = 20;
struct node_s {
  char name[String_Size];
  struct node_s* next;
}
struct node_s list[10];