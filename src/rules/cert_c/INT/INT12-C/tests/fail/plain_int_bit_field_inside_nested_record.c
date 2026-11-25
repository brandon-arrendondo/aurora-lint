/*
 * Rule: INT12-C
 * Source: synthetic
 * Status: FAIL - Should trigger INT12-C violation
 * Expect: count=3
 *
 * A plain int bit-field inside a nested structure or union is reported
 * once, by its own name, and not again for the member that holds it; a
 * typedef of plain `int` is plain int too (C11 6.7.2p5).
 */

typedef int word;

struct packet {
  struct {
    int kind : 4;
    unsigned int level : 4;
  } header;
  union {
    int raw : 8;
    unsigned char byte;
  } body;
  word tag : 6;
};
