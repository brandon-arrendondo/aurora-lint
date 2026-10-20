/*
 * Rule: MEM05-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM05-C violation
 * Description: sizeof of an operand whose type cannot be variably modified
 * is an integer constant expression, so each array is fixed-size: a string
 * literal, which has a fixed array type; a struct member, reached through
 * an object or a pointer, since no member is variably modified (C23
 * 6.7.2.1); and a typedef declared at file scope, since a VLA type can be
 * declared only in a block.
 */
struct addr { char arr[260]; };
struct conn { unsigned char psk[32]; };
struct proto { char vers[8]; };
typedef unsigned int word;

void constant_operands(struct addr s, struct conn *c, struct proto *pp) {
    char t[sizeof("255.255.255.255")];
    char d[sizeof "Mon Apr 13 12:34:56 1975"];
    char b[sizeof(s.arr) * 2];
    char p[2 * sizeof(c->psk) + 1];
    char v[sizeof(pp->vers)];
    char w[sizeof(word)];
    (void)t; (void)d; (void)b; (void)p; (void)v; (void)w;
}
