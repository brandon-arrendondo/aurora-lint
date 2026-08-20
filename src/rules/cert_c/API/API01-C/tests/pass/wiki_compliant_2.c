/*
 * Rule: API01-C
 * Source: wiki
 * Status: PASS - Should NOT trigger API01-C violation
 */

const size_t String_Size = 20;
struct node_s {
  struct node_s* next;
  char* name;
};
