/*
 * Rule: DCL05-C
 * Source: real-world (valkey src/dict.h `void(callback)(dict *)`,
 *         src/modules/lua/script_lua.c `LUALIB_API int(luaopen_cjson)(lua_State *L)`, task 1173)
 * Status: PASS - Should NOT trigger DCL05-C violation
 *
 * Both parse as a function declarator directly inside another with no
 * pointer between them -- a shape C cannot express (no function returns a
 * function), so it is a parse artefact and never nesting.
 */

typedef struct dict dict;
typedef struct lua_State lua_State;

void dictEmpty(dict *d, void(callback)(dict *));

#define LUALIB_API extern
LUALIB_API int(luaopen_cjson)(lua_State *L);
