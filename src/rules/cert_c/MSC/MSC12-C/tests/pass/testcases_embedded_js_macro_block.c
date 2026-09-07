/*
 * Rule: MSC12-C
 * Status: PASS - JavaScript inside a macro argument is not C.
 *
 * emscripten's EM_ASM takes a block of JavaScript as a macro argument.
 * tree-sitter has no preprocessor, so it parses that block as C: the JS
 * `catch (e) { }` becomes a function definition named `catch` with an empty
 * body, nested inside the enclosing C function. C has no nested function
 * definitions, so an empty one is always the parser reading something that
 * is not C (task 1005; raylib's rcore_web.c does exactly this).
 */

#define EM_ASM(code, ...) do { } while (0)

void set_rumble(int gamepad)
{
    EM_ASM({
        try
        {
            navigator.getGamepads()[$0].hapticActuators[0].pulse(1.0);
        }
        catch (e) { }
    }, gamepad);
}
