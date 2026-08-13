/*
 * Rule: DCL40-C
 * Status: PASS - trailing attribute-position macro after struct body is not
 * a redeclared object, even though every struct below uses the same macro
 * name (hostap's STRUCT_PACKED idiom)
 */

#define STRUCT_PACKED __attribute__((packed))

struct foo {
	int a;
	char b;
} STRUCT_PACKED;

struct bar {
	long c;
	short d;
} STRUCT_PACKED;

struct baz {
	char e[4];
} STRUCT_PACKED;
