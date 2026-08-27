/*
 * Rule: MSC13-C
 * Source: raylib (adapted, task 439 batch d / task 444)
 * Status: PASS - Should NOT trigger MSC13-C violations
 *
 * Emscripten's EM_ASM({ ... }) macro embeds raw JavaScript inside C source
 * for the web/wasm build target. tree-sitter-c has no idea it's JS, so it
 * tries to parse it as C: `const width = $0;` gets misread as a
 * `type_qualifier(const) type_identifier(width)` pair followed by an ERROR
 * node, with `$0` recovered as a bare `identifier` sitting inside that
 * ERROR-tainted `declaration`. Before this fixture, MSC13-C's
 * "declared but never used" pass had no error-node guard and flagged that
 * recovered `$0`/`$1`/`$2` fragment as a real phantom variable declaration.
 */

void copyFramebufferToCanvas(int screenWidth, int screenHeight, unsigned int *pixels) {
    EM_ASM({
        const width = $0;
        const height = $1;
        const ptr = $2;

        const canvas = Module.canvas;
        const ctx = canvas.getContext('2d');

        if (!Module.__img || (Module.__img.width !== width) || (Module.__img.height !== height)) {
            Module.__img = ctx.createImageData(width, height);
        }

        const src = HEAPU8.subarray(ptr, ptr + width * height * 4);
        Module.__img.data.set(src);
        ctx.putImageData(Module.__img, 0, 0);
    }, screenWidth, screenHeight, pixels);
}
