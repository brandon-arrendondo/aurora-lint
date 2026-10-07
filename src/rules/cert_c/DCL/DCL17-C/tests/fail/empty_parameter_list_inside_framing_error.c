/*
 * Rule: DCL17-C
 * Source: regression
 * Status: FAIL - legacy is declared with an empty parameter list
 *
 * The K&R-style prototype sits inside a parser ERROR region and is still
 * a file-scope declaration.
 *
 * The C2S run below is a macro that expands to a case label, which
 * tree-sitter cannot parse as a statement: with this many of them its
 * recovery wraps the rest of the file in ONE ERROR node. Recovery reads the
 * run and the next definition (absorbed) as one bogus function, so what
 * follows reaches the ERROR intact, as its children, and parses normally
 * (ADR-0008). A walk over file-scope items has to look through that node
 * the way it looks through an #if arm.
 */
#define C2S(x) case x: return #x;

static const char *cmd_name(int cmd)
{
	switch (cmd) {
	C2S(CMD_0)
	C2S(CMD_1)
	C2S(CMD_2)
	C2S(CMD_3)
	C2S(CMD_4)
	C2S(CMD_5)
	C2S(CMD_6)
	C2S(CMD_7)
	C2S(CMD_8)
	C2S(CMD_9)
	C2S(CMD_10)
	C2S(CMD_11)
	C2S(CMD_12)
	C2S(CMD_13)
	C2S(CMD_14)
	C2S(CMD_15)
	C2S(CMD_16)
	C2S(CMD_17)
	C2S(CMD_18)
	C2S(CMD_19)
	C2S(CMD_20)
	C2S(CMD_21)
	C2S(CMD_22)
	C2S(CMD_23)
	}
	return "unknown";
}

static int absorbed(void)
{
	return 0;
}

int legacy();

int caller(void)
{
	return legacy();
}
