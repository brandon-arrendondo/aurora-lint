# Thread-API families: reading the concurrency rules API-neutrally

**Status:** ruled 2026-10-11 (§8). Implementation starts with CON30-C and
CON36-C.

## 1. Problem

CERT's concurrency titles name a hazard, not an API: "Clean up thread-specific
storage" (CON30-C), "Wrap functions that can spuriously wake up in a loop"
(CON36-C). The 2026-10-07 rulings read them that way. E10 says the C11/POSIX
twins share one analysis keyed by API, concurrency hazards are read
API-neutrally, C11 and POSIX are built in, and RTOS families are declarable.
E2 says detectors resolve by declaration, not spelling (ADR-0006).

The detectors do not do this today:

- **Every CON/POS rule recognizes its API by the exact text of the callee.**
  Each compares `get_node_text(function)` against a private `matches!` list or
  a local `const` array. No rule resolves the callee to a declaration. The
  lookups that do exist (CON03, CON07, CON32, CON34, POS50) resolve variables,
  not callees.
- **The name lists are copies.** The same 4-name lock/unlock set appears in
  CON07, CON08 and CON32. A 6-name set appears in CON01 and CON09. The
  create/join/detach pairs appear in CON04, CON34, CON37, CON39 and CON50. The
  sync-type lists appear in CON03, CON06, CON07 and CON50.
- **The twins share no code.** CON35/POS51, CON32/POS49, CON05/POS52,
  CON31/POS48 and CON34/POS50 are each written separately. POS48 and POS49 are
  line-substring matchers.
- **There are gaps where a family is only half covered.**
  - CON36-C knows `cnd_wait` and `cnd_timedwait`, but not `pthread_cond_wait`.
  - CON30-C knows the `tss_*` calls, but not `pthread_key_create` or
    `pthread_setspecific`.
  - No rule models `cnd_broadcast` or `pthread_cond_broadcast`, `call_once` or
    `pthread_once`, rwlocks, or thread exit.
- **There is one structured table, and it is not configurable.**
  `src/analyze/concurrency_roots.rs` has `THREAD_SPAWN_APIS`, a list of
  (name, entry-argument index, exact arity). It feeds the reachability gate
  for CON03 and CON07, and it already holds Zephyr's `k_thread_create` /
  `k_work_init*` and Win32's `CreateThread`.
- **The threading check in `relevance.rs` is a raw substring search.** It
  looks for `pthread_`, `mtx_`, `atomic_` and similar over file text, comments
  included. It only writes an info line and gates nothing.
- **FreeRTOS appears nowhere.**

## 2. The model: operations, roles, families

A **family** is a named set of **operation declarations**. Each declaration
says that a function or function-like macro performs one **operation kind**,
and where its operands are. Rules ask about operation kinds and never about
names.

### Operation kinds and their roles

Positions are 1-based, as in `[environment.deallocators]`.

| Kind | Roles | C11 | POSIX |
|---|---|---|---|
| `thread_create` | `entry`, `arg`, `handle`, `arity` | `thrd_create` (entry 2, arg 3, handle 1, arity 3) | `pthread_create` (entry 3, arg 4, handle 1, arity 4) |
| `thread_join` | `handle` | `thrd_join` | `pthread_join` |
| `thread_detach` | `handle` | `thrd_detach` | `pthread_detach` |
| `thread_self` | — | `thrd_current` | `pthread_self` |
| `thread_exit` | — | `thrd_exit` | `pthread_exit` |
| `mutex_init` | `object` | `mtx_init` | `pthread_mutex_init` |
| `mutex_lock` | `object`, `blocking` (always / timeout / never) | `mtx_lock` (always), `mtx_timedlock` (timeout), `mtx_trylock` (never) | `pthread_mutex_lock`, `pthread_mutex_timedlock`, `pthread_mutex_trylock` (same three) |
| `mutex_unlock` | `object` | `mtx_unlock` | `pthread_mutex_unlock` |
| `mutex_destroy` | `object` | `mtx_destroy` | `pthread_mutex_destroy` |
| `cond_wait` | `cond`, `mutex`, `spurious` | `cnd_wait`, `cnd_timedwait` | `pthread_cond_wait`, `pthread_cond_timedwait` |
| `cond_signal` | `cond` | `cnd_signal` | `pthread_cond_signal` |
| `cond_broadcast` | `cond` | `cnd_broadcast` | `pthread_cond_broadcast` |
| `tss_create` | `key`, `destructor` | `tss_create` (key 1, destructor 2) | `pthread_key_create` (key 1, destructor 2) |
| `tss_set` | `key` / `slot`, `value`, `destructor` | `tss_set` (key 1, value 2) | `pthread_setspecific` (key 1, value 2) |
| `tss_get` | `key` / `slot` | `tss_get` | `pthread_getspecific` |
| `tss_delete` | `key` | `tss_delete` | `pthread_key_delete` |
| `once` | `flag`, `function` | `call_once` | `pthread_once` |
| `sleep` | — | `thrd_sleep` | `nanosleep`, `sleep`, `usleep` (the last two are pre-2008) |

Type kinds (`mutex`, `cond`, `thread`, `tss_key`, `once_flag`) map `mtx_t`,
`pthread_mutex_t` and so on. They replace the per-rule type-substring lists in
CON03, CON06, CON07 and CON50, and they resolve through
`resolve_typedef_chain`, as CON03's `declares_lock` already does.

**Atomics stay where they are.** `_Atomic` and `<stdatomic.h>` are language
and library features, not a thread API. An RTOS's own atomics can be a later
kind.

**Two roles carry a hazard's meaning.**

- **`cond_wait.spurious`** is `true` for C11 and POSIX. CON36-C fires only on
  a wait whose family declares that it can wake spuriously. A FreeRTOS
  semaphore take does not. Zephyr's `k_condvar_wait` does.
- **Where a destructor comes from.** In C11 and POSIX it comes from key
  creation: CON30-C asks whether the key was created without one. A family
  with fixed slots and no key creation can attach the destructor to the set
  call instead. This is why `tss_set` carries an optional `destructor` role.

## 3. Built-in families

| Family | When it is in force | Tier (E14) |
|---|---|---|
| `c11` | Always. | Tier 1. |
| `posix` | See §5. | Tier 1. A missing declaration has a safe default (§5). |
| Named RTOS profiles (`freertos` now; `zephyr` and `threadx` later) | Only when the project names them. | Tier 2: in scope only when declared. |
| A project's own operations | Only when declared. | Tier 2. |

The built-in tables live in one module,
`src/utility/cert_c/thread_api.rs`. That module is a role-query layer, the
same shape as `call_roles.rs` for allocators. It answers, for one call node,
`thread_op(call, source, ctx) -> Option<ThreadOp { kind, family, roles }>`.
Rules call it and keep no name lists of their own.
`concurrency_roots::THREAD_SPAWN_APIS` becomes a view of every `thread_create`
declaration in force, so a declared FreeRTOS `xTaskCreate` also roots the
CON03/CON07 reachability gate.

The Zephyr and Win32 names that are hard-coded today are recognized by CON03,
CON07, CON31, CON37, POS49 and the roots table. They are kept as they are in
the first step (see question 3).

## 4. Declaring a family: the settings format

These are project facts, so they go under `[environment]`, next to the
allocators. Like the allocators, they survive `--profile`: a preset chooses a
reading and never erases what a project's own functions do. They are added to
`project_facts`, the settings hash and `--write-config`.

```toml
[environment.threads]
# Built-in profiles to load, by name. c11 needs no entry.
families = ["freertos"]
# Optional, POSIX only: "auto" (the default, see §5) or "off".
posix = "auto"

# A project's own wrappers, and RTOS calls no profile covers.
[environment.threads.functions]
os_mutex_lock   = { op = "mutex_lock", object = 1 }
os_mutex_unlock = { op = "mutex_unlock", object = 1 }
os_task_spawn   = { op = "thread_create", entry = 2, arg = 3, arity = 5 }
os_cond_wait    = { op = "cond_wait", cond = 1, mutex = 2, spurious = true }

[environment.threads.types]
os_mutex_t = "mutex"
```

Command-line equivalents in the style of `--allocator` (`--thread-family
NAME`, `--thread-op NAME=KIND[:ROLE=N,...]`) are a later step. The manifest
table is the only way to declare in the first step.

**Validation.** It runs at settings resolution, as `MemoryDeclarations::validate`
does, and it refuses rather than ignoring:

- an unknown table, key, kind or role, by name, with the allowed set
  (`deny_unknown_fields`, as everywhere else in `[environment]`);
- a missing required role (for example `thread_create` without `entry`), or
  a role the kind does not take;
- a position of 0, or one past `arity` when `arity` is given;
- a name that is not a C identifier;
- a name the built-in `c11`/`posix` tables already define ("'pthread_mutex_lock'
  is a POSIX function; its contract is the library's");
- a name declared twice with different contracts, including across a named
  profile and `functions`;
- an unknown profile name, with the shipped list.

**Install.** Declarations are installed once per process before prescan:
`threads::declare()` / `declared()`, a `OnceLock` as in
`settings/memory.rs`. Function summaries and the roots table are built in
prescan, so a later declaration would reach some tables and not others.
Changing a declaration changes the settings hash, so the prescan cache keys on
it. I expect to need one cache-format bump, and will ask before taking 44.

**Identity follows ADR-0006 and E2.** A declared name is matched when the call
resolves to that function or macro. A function-like macro is followed through
`macro_expand`, which matters for FreeRTOS: `xSemaphoreTake` is a macro over
`xQueueSemaphoreTake`. The first step matches the macro's name at the call
site, as the profile lists it; following a project's own macro around one is
a later step. A callee that resolves to an object of the same name (a local,
a parameter, or a file-scope function pointer) is that object and performs
no operation. `arity` keeps its current job of refusing a same-named
function with the wrong argument count.

**A project that defines a reserved name keeps the library's contract.**
ISO C reserves the `thrd_`, `mtx_`, `cnd_` and `tss_` prefixes and POSIX
reserves `pthread_` for the implementation. A project that defines
`pthread_cond_wait` itself, as a shim over another platform's API for
example, is supplying that interface, and its callers rely on that contract.
This differs from what this note first proposed: the project's definition
does not take the call out of the family. It is also why a declaration may not
restate a built-in name.

## 5. What each preset does with an undeclared family

This is the main point that needs Brandon's ruling.

ADR-0015's 2026-10-08 amendment leaves no "discovered" class: facts come from
configuration or a compile database, never from the host. The task wording,
"POSIX detected by default from resolved declarations/includes", has to be
squared with that. I propose drawing the line as follows.

**Which family a call belongs to is identity, not an environment fact.**
Deciding that a call resolves to the `pthread_cond_wait` that `<pthread.h>`
declares is ADR-0006 resolution, of the same sort as every other
callee-identity question the engine answers from the source it is given. That
is "detection" in the ruling's sense, and it needs no fact about the host. The
environment fact, `posix_version`, still says which POSIX edition the code is
judged against.

Under that reading:

| Situation | `default` | `strict` | `pedantic` |
|---|---|---|---|
| C11 call | recognized | recognized | recognized |
| A POSIX call that resolves to a system-header declaration, or that has no visible declaration and no project definition | recognized: default assumes POSIX | recognized: the reserved name is the library's, so the hazard is reported, which is strict's direction | recognized, plus the existing `posix_notice` naming `posix_version` when it is undeclared |
| `posix_version = "none"` declared, or `threads.posix = "off"` | POSIX family off | off | off |
| An RTOS profile or project operations not declared | nothing: those calls are unknown functions | nothing | nothing (no spelling-based "looks like FreeRTOS" notice; that would be discovery by spelling) |
| An RTOS profile or project operations declared | in force | in force | in force |

All three presets therefore read a declared family the same way. Presets
differ only in the existing POSIX environment stance. Whether a POSIX
*edition* matters per operation (for example `usleep` was removed in 2008)
goes through the existing `posix_for(file)` gate, unchanged.

**The `POS*` rules stay POSIX-only.** Their titles name POSIX. Each `CON*`
twin gets the API-neutral analysis. Both fire on a POSIX call, which is E10's
existing overlap policy (`docs/design/cross-rule-overlap.md`).

## 6. What the FreeRTOS profile contains

The names and signatures below were checked against FreeRTOS-Kernel V11.2.0
(`include/task.h`, `include/semphr.h`), and the profile cites that version.
The last row says which entries ship in the first step.

| Kind | FreeRTOS |
|---|---|
| `thread_create` | `xTaskCreate` (entry 1, arg 4, handle 6, arity 6), `xTaskCreateStatic` (entry 1, arg 4, arity 7) |
| `thread_exit` | `vTaskDelete(NULL)`. With a non-null handle it deletes *another* task, which is a separate hazard, close to POS44 but not POS44 itself. Out of the first step. |
| `thread_join` / `thread_detach` | none: tasks are not joinable. CON04-C and CON39-C have nothing to say about FreeRTOS tasks. |
| `mutex_init` | `xSemaphoreCreateMutex`, `xSemaphoreCreateRecursiveMutex`. Both return a handle, so `object` is the return value. |
| `mutex_lock` | `xSemaphoreTake(h, ticks)` (blocking: timeout; `portMAX_DELAY` means always), `xSemaphoreTakeRecursive` |
| `mutex_unlock` | `xSemaphoreGive`, `xSemaphoreGiveRecursive` |
| `mutex_destroy` | `vSemaphoreDelete` |
| global critical section | `taskENTER_CRITICAL` / `taskEXIT_CRITICAL`, `vTaskSuspendAll` / `xTaskResumeAll`. This is a lock with no object, so it needs a `critical_enter`/`critical_exit` kind or `object = none`. Open item. |
| `cond_wait` | none. FreeRTOS has no condition variable, so CON36-C does not apply. Task notifications and event groups do not wake spuriously in the CON36 sense. |
| shipped in the first step | Checked against FreeRTOS-Kernel V11.2.0. The plain `xSemaphoreTake`/`xSemaphoreGive` are left out, since they serve binary and counting semaphores too, and a call is a lock only when its handle came from a mutex-creating call. The recursive forms ship, along with the mutex-creating calls, task creation, the storage pointers and the delays. `vTaskDelete` is left out (see `thread_exit`). |
| `tss_set` / `tss_get` | `vTaskSetThreadLocalStoragePointer(task, index, value)` / `pvTaskGetThreadLocalStoragePointer(task, index)`. These are fixed slots with no destructor in the vanilla kernel. A destructor-carrying set exists as a vendor extension (ESP-IDF's `...AndDelCallback`) and would be a separate `esp-idf` profile. So for FreeRTOS, CON30-C's hazard reads: a heap value stored in a slot and not freed before the task deletes itself. |
| `sleep` (blocking, for CON05-C) | `vTaskDelay`, `xTaskDelayUntil`, plus queue receive/send and notify-take calls with a non-zero timeout |
| types | `TaskHandle_t` → thread, `SemaphoreHandle_t` → mutex. A semaphore handle is not always a mutex; it is a mutex only when made by a `CreateMutex` call. Open item. |

## 7. Plan after review

1. Add `thread_api.rs` with the c11 and posix tables and the settings schema,
   validation, install and docs (a `configuration.rst` section and a FreeRTOS
   example).
2. **CON30-C and CON36-C.** Port them to `thread_op`, and add the POSIX
   coverage (`pthread_key_*`, `pthread_setspecific`, `pthread_cond_*wait`).
   Fixtures per family: c11, posix, a declared project family, freertos (CON30
   only; CON36 expects nothing), and a project function that shadows a library
   name.
3. **A local A/B on the real-world corpora** with a frozen binary on each side.
   CON30 and CON36 should only gain findings, all at POSIX call sites. Any
   lost finding is a regression to explain. Adjudication stays held.
4. **The other CON/POS rules**, one per commit, with the E10 twins sharing the
   analysis. Fold the roots table, and make `relevance.rs` count the families
   in force.

## 8. Rulings (maintainer, 2026-10-11)

1. **POSIX recognition is identity, in every preset.** A call that resolves to
   the library's declaration, or to a reserved name no project definition
   shadows, belongs to the POSIX family. This is resolution under ADR-0006,
   not a discovered host fact, so the 2026-10-08 amendment to ADR-0015 is not
   in tension with it. `posix_version = "none"` or `threads.posix = "off"`
   turns the family off.
2. **The format is the structured one in §4:** `[environment.threads]` with
   `families`, `functions` (inline tables of `op` plus 1-based roles) and
   `types`. It refuses everything listed there, including redefining a
   built-in name, and denies unknown fields.
3. **The hard-coded Zephyr and Win32 names stay always on for now.** A later
   step moves them into `zephyr` and `win32` profiles, once a Zephyr
   real-world oracle exists to measure what declaring them changes.
4. **RTOS profiles ship in-tree and version-pinned.** `families =
   ["freertos"]` names a shipped profile. The profile is checked against
   pinned kernel source and states the kernel version it matches.
