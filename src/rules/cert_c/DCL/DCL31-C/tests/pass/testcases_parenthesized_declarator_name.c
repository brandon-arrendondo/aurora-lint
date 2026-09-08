/*
 * Rule: DCL31-C
 * Source: task 1040 (lua lua.h:204, lauxlib.h:108)
 * Status: PASS - `LUA_API T (name) (args);` declares `name`, so calling it
 * is not an implicit declaration.
 *
 * lua wraps every public name in parentheses to keep it out of macro
 * expansion. With the return type spelled as two identifiers -- the export
 * macro plus the real type -- tree-sitter cannot tell that parenthesized
 * declarator from a parameter list: it reads the *type* as the declared name
 * and the real name as that "function"'s only parameter. The declaration was
 * therefore collected under the wrong name and every call to the right one
 * was flagged.
 */

typedef struct lua_State lua_State;
typedef unsigned long lua_Unsigned;
typedef long lua_Integer;

LUA_API lua_Unsigned (lua_rawlen) (lua_State *L, int idx);
LUA_API lua_Integer (luaL_len) (lua_State *L, int idx);

int use_lua(lua_State *L)
{
    return (int)lua_rawlen(L, 1) + (int)luaL_len(L, 2);
}
