/*
 * Rule: API01-C
 * Source: wiki
 * Status: FAIL - Should trigger API01-C violation
 */

const size_t String_Size = 20;
struct node_s {
  char name[String_Size];
  struct node_s* next;
};
