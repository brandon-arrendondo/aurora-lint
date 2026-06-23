# raylib Upstream Bugfix PRs — Tier 1

Surfaced by the sqc real-world audit of **raylib @ `962bbfc`** (ground-truth oracle `raylib-v1.0`, task 227).
These are the **Tier 1** findings: genuine public-API memory-safety bugs reachable with *ordinary* inputs —
**independent of raylib's "load trusted assets only" threat model**. In two of three, the author's own
guard is present but ineffective, and all three have bounds-checking *siblings*, so each is a clear
oversight rather than intent.

Upstream repo: <https://github.com/raysan5/raylib>. Target branch for PRs: typically `master`.
Each bug gets its own branch + PR (review → test case → PR description), tackled one at a time.

---

## Bug 1 — `rlPushMatrix()` matrix-stack buffer overflow  ⬜ not started

- **File / lines:** `src/rlgl.h:1239-1250` (guard at 1240, OOB write at 1248)
- **Symbol:** `void rlPushMatrix(void)` (public `RLAPI`)
- **Array:** `Matrix stack[RL_MAX_MATRIX_STACK_SIZE]` (`rlgl.h:1081`), `RL_MAX_MATRIX_STACK_SIZE == 32` (`rlgl.h:225`)
- **Severity:** OOB write of one 64-byte `Matrix` (and growing) into adjacent `RLGL.State` fields. High.

### The bug
```c
void rlPushMatrix(void)
{
    if (RLGL.State.stackCounter >= RL_MAX_MATRIX_STACK_SIZE) TRACELOG(RL_LOG_ERROR, "RLGL: Matrix stack overflow (RL_MAX_MATRIX_STACK_SIZE)");
    // ^ logs but does NOT return / else — execution falls through

    if (RLGL.State.currentMatrixMode == RL_MODELVIEW) { ... }

    RLGL.State.stack[RLGL.State.stackCounter] = *RLGL.State.currentMatrix;  // 1248: writes stack[32] when stackCounter==32
    RLGL.State.stackCounter++;                                              // then 33, 34, ... on further pushes
}
```
The overflow check has no `return` and no `else`, so the assignment runs unconditionally. The 33rd
unbalanced `rlPushMatrix()` writes `stack[32]` — one element past the array — and subsequent pushes
keep writing further out of bounds, clobbering adjacent `RLGL.State` members.

### Why it's a clear bug (not threat-model-dependent)
- The guard *exists* — the author intended to prevent overflow and simply omitted the early return.
- The matching `rlPopMatrix()` (rlgl.h:1255) **is** correctly guarded (`if (RLGL.State.stackCounter > 0)`).
  The asymmetry is the tell.
- Reachable via the public API with ordinary use (deeply nested `rlPushMatrix` without matching pops).

### Proposed fix (matches raylib style)
```c
if (RLGL.State.stackCounter >= RL_MAX_MATRIX_STACK_SIZE)
{
    TRACELOG(RL_LOG_ERROR, "RLGL: Matrix stack overflow (RL_MAX_MATRIX_STACK_SIZE)");
    return;
}
```
Drop the push when full (pop side already tolerates this). Confirm no caller relies on the
counter incrementing past the cap.

### Test plan
- `rlPushMatrix` only touches `RLGL.State` (no live GL calls), so a **headless repro** is possible:
  include rlgl with implementation, call `rlPushMatrix()` `RL_MAX_MATRIX_STACK_SIZE + 4` times,
  build with `-fsanitize=address`, assert ASan reports a global/stack overflow *before* the fix and
  is clean after.
- Negative control: balanced push/pop loops stay clean both before and after.

### PR description (draft)
> **Fix matrix stack overflow in `rlPushMatrix()`**
> The `RL_MAX_MATRIX_STACK_SIZE` check in `rlPushMatrix()` logs an error but does not return, so the
> matrix is still written to `RLGL.State.stack[stackCounter]` — an out-of-bounds write once the stack
> is full (`stackCounter == RL_MAX_MATRIX_STACK_SIZE`), corrupting adjacent `RLGL.State` fields and
> growing with each further push. `rlPopMatrix()` already guards the symmetric case. This adds the
> missing early return. (ASan repro + before/after included.)

---

## Bug 2 — `TextReplaceBetween()` static-buffer overflow  ⬜ not started

- **File / lines:** `src/rtext.c:1900-1928` (overflowing `strncpy`s at 1922-1924)
- **Symbol:** `char *TextReplaceBetween(const char *text, const char *begin, const char *end, const char *replacement)` (public `RLAPI`)
- **Buffer:** `static char buffer[MAX_TEXT_BUFFER_LENGTH]`, `MAX_TEXT_BUFFER_LENGTH == 1024` (`rtext.c:104`)
- **Severity:** OOB write into a file-static buffer with caller-controlled length. High.

### The bug
```c
static char buffer[MAX_TEXT_BUFFER_LENGTH] = { 0 };
...
strncpy(buffer, text, beginIndex + beginLen);                                   // 1922
if (replacement != NULL) strncpy(buffer + beginIndex + beginLen, replacement, replaceLen); // 1923
strncpy(buffer + beginIndex + beginLen + replaceLen, text + endIndex, textLen - endIndex);  // 1924
```
Total bytes written ≈ `textLen + replaceLen - (endIndex - beginIndex - beginLen)`, with **no clamp
against `MAX_TEXT_BUFFER_LENGTH`**. Any sufficiently long `text`/`replacement` overflows the 1024-byte
static buffer.

### Why it's a clear bug
- Sibling functions clamp: `TextReplace` guards `< MAX_TEXT_BUFFER_LENGTH - 1` and `TextInsert` guards
  its lengths before copying. `TextReplaceBetween` omits the guard.
- Reachable with ordinary large strings via the public API — no malformed file needed.

### Proposed fix
Mirror `TextReplace`/`TextInsert`: bail out (return `text` or the empty buffer) when the computed
result length would reach `MAX_TEXT_BUFFER_LENGTH`, and/or clamp each `strncpy` length to the
remaining capacity. Settle the exact shape against the sibling style during implementation.

### Test plan
- **Pure string function — trivially headless.** Call with `text` long enough that
  `result length >= MAX_TEXT_BUFFER_LENGTH`; build with ASan → overflow before, clean (and correct/truncated
  per the chosen policy) after.
- Correctness controls: short inputs produce byte-identical output before and after the fix.

### PR description (draft)
> **Fix buffer overflow in `TextReplaceBetween()`**
> `TextReplaceBetween()` copies into the 1024-byte `static char buffer[MAX_TEXT_BUFFER_LENGTH]` with
> three `strncpy` calls whose combined length is driven by the (caller-controlled) input lengths and is
> never clamped to the buffer size — overflowing for long inputs. The sibling `TextReplace`/`TextInsert`
> already guard against `MAX_TEXT_BUFFER_LENGTH`; this brings `TextReplaceBetween` in line. (ASan repro
> + before/after included.)

---

## Bug 3 — Unchecked gamepad index OOB in `GetGamepadAxisCount()` / `GetGamepadName()`  ⬜ not started

- **File / lines:** `src/rcore.c:4000-4003` (`GetGamepadAxisCount`), `src/rcore.c:3935-3938` (`GetGamepadName`)
- **Symbols:** `int GetGamepadAxisCount(int gamepad)`, `const char *GetGamepadName(int gamepad)` (public `RLAPI`)
- **Arrays:** `int axisCount[MAX_GAMEPADS]` (`rcore.c:372`), `char name[MAX_GAMEPADS][MAX_GAMEPAD_NAME_LENGTH]` (`rcore.c:374`), `MAX_GAMEPADS == 4` (`rcore.c:238`)
- **Severity:** OOB read with a caller-supplied index. Medium (read, small array).

### The bug
```c
int GetGamepadAxisCount(int gamepad)   { return CORE.Input.Gamepad.axisCount[gamepad]; }   // no bound
const char *GetGamepadName(int gamepad){ return CORE.Input.Gamepad.name[gamepad]; }        // no bound
```
`gamepad` is an unvalidated public-API argument indexing fixed `[MAX_GAMEPADS]` arrays.

### Why it's a clear bug
- **Every** sibling validates: `IsGamepadAvailable`, `IsGamepadButtonPressed/Down/Released/Up`,
  `GetGamepadAxisMovement` all gate on `(gamepad < MAX_GAMEPADS) && CORE.Input.Gamepad.ready[gamepad]`
  (rcore.c:3929/3945/3958/3971/3984/4010). These two getters are the only ones missing the guard.

### Proposed fix
Add the same guard used by the siblings, returning a safe default:
```c
int GetGamepadAxisCount(int gamepad)
{
    if ((gamepad < 0) || (gamepad >= MAX_GAMEPADS)) return 0;
    return CORE.Input.Gamepad.axisCount[gamepad];
}
const char *GetGamepadName(int gamepad)
{
    if ((gamepad < 0) || (gamepad >= MAX_GAMEPADS)) return NULL;
    return CORE.Input.Gamepad.name[gamepad];
}
```
(Note: siblings only check `< MAX_GAMEPADS`, not `>= 0` — propose adding the lower bound too, or match
sibling style exactly to keep the PR minimal. Decide during review.)

### Test plan
- Build raylib as a lib with ASan; from a headless harness call `GetGamepadAxisCount(9999)` /
  `GetGamepadName(-1)` → OOB read before the fix, safe default after. (`CORE` is file-static; the
  harness links the built lib and calls the public API — no window/GL needed for these getters.)
- Control: `gamepad` 0..MAX_GAMEPADS-1 unchanged.

### PR description (draft)
> **Bounds-check gamepad index in `GetGamepadAxisCount()` and `GetGamepadName()`**
> These two public getters index `CORE.Input.Gamepad.axisCount[gamepad]` / `name[gamepad]` with an
> unvalidated `gamepad` argument, an out-of-bounds read for `gamepad >= MAX_GAMEPADS`. Every sibling
> gamepad accessor already guards with `gamepad < MAX_GAMEPADS`; this adds the same check, returning a
> safe default.

---

## Workflow (per bug)
1. Branch off raylib `master` (one branch per bug).
2. Re-read the function + siblings; confirm the fix shape matches raylib conventions.
3. Write a minimal ASan repro (before = overflow/OOB, after = clean); keep it in our scratch, attach
   the relevant snippet to the PR.
4. Apply the fix; rebuild; re-run repro.
5. Finalize PR description; open PR (Brandon to confirm raylib's PR/CLA process first).

## Status
| # | Bug | Branch | Repro | Fix | PR |
|---|-----|--------|-------|-----|----|
| 1 | `rlPushMatrix` stack overflow | ⬜ | ⬜ | ⬜ | ⬜ |
| 2 | `TextReplaceBetween` buffer overflow | ⬜ | ⬜ | ⬜ | ⬜ |
| 3 | gamepad-index OOB (`GetGamepadAxisCount`/`GetGamepadName`) | ⬜ | ⬜ | ⬜ | ⬜ |

Tier 2 (malformed-file robustness: IQM/BDF/OBJ/glTF parsers — task 233) and Tier 3 (platform input
callbacks) are tracked separately and not part of this detour.
