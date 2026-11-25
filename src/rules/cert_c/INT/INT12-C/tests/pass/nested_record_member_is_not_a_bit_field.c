/*
 * Rule: INT12-C
 * Source: synthetic
 * Status: PASS - Should not trigger INT12-C violation
 *
 * A member that is a structure, union or enumeration is not a bit-field,
 * even when bit-fields or a `:` appear inside its body; an unnamed
 * bit-field names nothing an expression reads; and explicitly signed or
 * unsigned bit-fields, or ones whose type names merely contain `int`, are
 * not plain int.
 */

typedef unsigned int point;

struct packet {
  struct {
    unsigned int kind : 4;
    signed int level : 4;
  } header;
  union {
    unsigned int raw : 8;
    unsigned char byte;
  } body;
  enum { ON, OFF } state;
  int : 3;
  signed flag : 1;
  unsigned width : 7;
  point x : 5;
};
