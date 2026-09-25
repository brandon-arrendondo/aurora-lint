# ADR conformance: known departures (v0.6.0)

**Status:** swept 2026-09-25 against `ca377036`, before the v0.6.0 freeze.
This doc goes stale as fixes land; the rows are the checklist.

## What this is

A read-only sweep of every rule and shared analysis primitive against the
labeling ADRs: ADR-0005 (misfires), ADR-0006 (resolve identifiers, don't
match spelling), ADR-0010 (every compilable configuration counts) and
ADR-0011 (what counts as proof). Each row is a place where detection
contradicts one of them. Assert handling (ADR-0010 Decision 5) was fixed
separately and is not listed.

## Tiers

- **Tier 1: fixed before v0.6.0.** Everything in section A (shared
  primitives), the EXP34-C rule-local proofs in section B, and STR38-C's
  nondeterministic output. One fix in a shared primitive changes many
  rules, and EXP34-C carries the published real-world figure.
- **Tier 2: known departures in v0.6.0, fixed in v0.6.x.** The rest of
  section B: rule-local rows, one change per rule family. Most are misfires
  (ADR-0005), so fixing them mainly removes false positives. Until a
  family lands, published per-rule figures for its rules carry this
  caveat.

Section C lists the rulings the fixes depend on; section D, items outside
these ADRs.

## Columns

- **Dir**: what a fix does to the output. `+` adds findings that a shortcut
  was suppressing; `-` removes findings a misfire was producing.
- **Conf**: C = confirmed in code; S = suspected, needs a probe; P = needs a
  policy ruling rather than a fix.
- **Covered**: whether a tracked change already covers it, or "new".
- Line numbers are approximate (±10). **[V]** rows were re-read a second
  time.

---

## A. Shared primitives. One fix reaches many rules, so do these first.

### A1. Caller-set proofs with no linkage gate (ADR-0011: caller set; libraries and -rdynamic count as external)

The correct pattern already exists as `prescan::seedable_param_states` and `callsite_param_proven_nonnull`, which are gated on `has_internal_linkage && !address_taken`. Every row below lacks that gate.

| where | shortcut | consumers | dir | size | conf | covered |
|---|---|---|---|---|---|---|
| prescan.rs `aggregate_callsite_int_args` (2016), plus the per-file call in analyze/mod.rs:945 **[V]** | A parameter is narrowed to the constants every caller passes. The only gate is `header_declared`. The per-file call passes `&HashSet::new()` as the header set, and its result overlays the project table. An exported fn with one in-file `f(2)` therefore gets range [2,2] in `value_range::build_initial_state`. | every VRA rule: ARR30, INT08/10/16/30/31/32/33/34 | + | 2 sites | C | new |
| prescan.rs `aggregate_callsite_validated_args` (2570) → ARR30 `param_validated_by_callers` | "Every call site guards the arg" makes the index parameter validated. No gate at all; its doc says header-declared fns are deliberately not skipped. | ARR30 | + | 1 fn (8 findings per 1335) | C | tracked |
| prescan.rs `aggregate_callsite_buf_args` (2388), `_field_buffer_sizes` (2443), `_taint_args` **[V]** | Gated only on `header_declared.contains(callee)`. A non-static fn with no header prototype, called through a pointer, or exported via -rdynamic is treated as having a closed caller set. | STR31 `caller_min_buffer_for_param`/`param_dest_bounded_by_caller`, ARR38 `copy_bounded_by_caller_struct_field`, STR02, FIO30 | + | 3 fns | C | new |
| int_provenance.rs `parameter_is_risky` (80) | A parameter counts as bounded when every known caller is taint-free. No linkage check, and the caller map is keyed by name. | INT30, INT31, INT32, FLP03 | + | +302 measured | C | tracked |
| ENV03/ENV33/STR02 `callers_are_all_clean` | Sink suppressed when every in-tree caller is clean. No linkage gate. ENV03 walks only one level. | ENV03, ENV33, STR02 | + | – | C | tracked |
| FIO30-C `is_potentially_unsafe_format_string` (1211-1245) | A format-string parameter is treated as safe when `has_local_caller && !param_is_interproc_tainted`. No linkage gate, and "not tainted" is weaker than "safe". | FIO30 | + | small | C | new (same class as the taint caller vote) |
| concurrency_roots.rs + prescan `compute_concurrency_reachable` (1057) | Code that nothing reaches from a thread root in the tree is treated as not concurrent (`if !is_reachable { continue; }`). Exported fns and globals of libraries or -rdynamic executables have external callers. Roots are also under-collected: no sigaction, pthread_once or field-dispatch spawns. | CON03, CON07 | + | medium | C | new |
| DCL19-C `check` (84-110) | The message asserts "only used within this file" for a non-static fn without considering other translation units or external linkage. | DCL19 | - / message | small | C | new |
| ARR30 `check_unvalidated_param_index` (2689), `is_subscript_violation` (3487); ARR00 `check_subscript_bounds` (1374) | A static fn with an enum- or typedef-typed index parameter is treated as proven safe, with no call-site check. A C enum does not constrain the value. | ARR30, ARR00 | + | small | C | new |
| ARR00 `check_loop_array_access` (1231) | "Function parameters are assumed to be valid" | ARR00 | + | trivial | C | new |

### A2. Implementation-defined widths used as proof (ADR-0011 basis 4)

These all assume LP64 with a 32-bit int and a signed char. **Ruling needed first:** An earlier design note says "int is 32-bit everywhere, correct", which predates ADR-0011 basis 4. Decide whether the tool pins a data model per corpus (the earlier design note's proposal) or stops suppressing on widths.

| where | shortcut | consumers | dir | conf | covered |
|---|---|---|---|---|---|
| ast_utils.rs `integer_type_width` (1571) | Its doc says: "pinned x86_64 LP64 model... callers use this to *suppress*". | INT08, INT31, INT34, API00 `is_defined_unsigned_shift`, EXP14 | + | C | related (data-model design note) |
| const_eval.rs `BUILTIN_LIMIT_MACROS` (253), `resolve_sizeof_type` (297) | INT_MAX=2^31-1, LONG_MAX=i64::MAX, CHAR_MIN=-128 and sizeof(long)=8 drive fits and non-zero proofs. The builtins win over a file's own #define. | INT08/10/30-34, FLP03, all const_eval users | both | C | new |
| const_eval `promoted_range_for_type` (233) + `PROMOTED_ARITH_BITS=32` | "narrow op narrow can't leave int" is true only for a 32-bit int. | INT08, INT30, INT32 | + | P | an earlier design note calls this correct; it conflicts with ADR-0011 |
| buffer_size.rs `sizeof_type_bytes` (118), `extract_sizeof_value` (168) | long/pointer/size_t = 8, wchar_t = 4. `extract_sizeof_value` falls back to a substring scan, then to "Default to pointer size" 8, so `sizeof(struct foo)` gives 8. | ARR30, ARR38, STR31 | both | C | new |
| value_range `extract_var_type_from_declaration` (203) | char is signed 8-bit, long is 64-bit. | all VRA rules | both | C | new |
| overflow_helpers `is_portable_64bit_signed` (511) | intptr_t and ptrdiff_t are called 64-bit "on every data model". | INT32 | + | C | new |
| rule-local: INT02 `classify` (410); INT30 `operand_width` (2376), `check_allocation_size_wrap` (1401), `calloc_product_fits` (1662); INT34 literal `1L` (~520); INT08 narrow +/- (~215); ARR38 `sizeof_type` (3041, incl. `"twoIntsStruct" => 8`); size_analysis `find_element_size` (unknown → 4); EXP36 alignment table; API07 `check_type_confusion`; STR31 `%d` = 11 chars | Same class, rule-side. | those rules | mostly + | C | new |

### A3. One configuration assumed, or exclusive #if arms merged (ADR-0010 D1/D4)

| where | shortcut | consumers | dir | conf |
|---|---|---|---|---|
| const_eval `collect_macro_constants` (484) → cfg.rs `evaluate_constant_condition` (917) | The first definition wins among live build-config arms (`#ifdef X #define F 0 #else #define F 1`), and the CFG then drops the branch as constant-false. The lookup is also by spelling, so a local that shadows a file-scope const or enumerator gets folded too (0006). | every CFG rule: EXP33, EXP34, MEM01, MSC13, ARR30, INT08/10/16/30-34, VRA | both | C |
| init_state.rs `collect_file_scope_constants` (2543) **[V]** | `type_text.contains("static") \|\| contains("const")`, so a mutable `static int debug = 0;` is a compile-time 0. It is keyed by name, so a shadowing local inherits it (0006). It walks every #if/#else arm and the last one wins. | FIO30 dead-branch pruning, EXP33 | both | C |
| const_eval `collect_non_const_static_defs` / `static_var_assigned_after` (666/726) | A mutable static counts as constant if a text scan finds no `X =`, `op=`, `X++` or `X--`. It misses `++X`, `&X` passed out, and writes through pointers, so the CFG prunes live branches (0011 b3). | CFG rules | - (misfire) / + | C |
| macro_expand `collect_function_macros` (89), `collect_rec` (780) | The first definition wins among arms the platform profile can't settle. `macro_nulls/frees/writes_param_indices` and bodies of ALWAYS/NEVER-style macros describe one arbitrary configuration. dead_regions.rs counts about 451 such names, with sqlite ALWAYS → (1) as its example. | EXP33/34/10/36, MSC13/37, ARR30, DCL13/31/41, MEM03/12/30/31, INT32/34, PRE31, WIN05 | both | C |
| const_eval `collect_macro_aliases` (422) via `merged_macro_aliases` | `#define ALIAS x` is collected from every arm and the last wins. WIN05 is the example: an #ifdef HKLM/HKCU choice drops the HKLM finding. | WIN05, STR02, ERR33, ENV03, ENV33 and about 10 more | + | C (primitive), S (impact) |
| guard_dominance.rs `BLOCK_LIKE_KINDS` (652) **[V]** | `preproc_else`/`preproc_elif` are treated as block level, so a guard in one arm is credited for a site in the other. The doc admits it. | has_dominating_comparison (API00, ARR30, ARR38), dominating_conditions (EXP33, INT30), the limit guard (INT30, INT32), has_dominating_dereference (null_state), call_arg_guards (ARR30) | + | C |
| noreturn.rs `infer_terminating_definitions` / `collect_noreturn_function_names` (158) | Definitions from exclusive #if arms go into one name set, so a name terminating in any arm is noreturn in all. | per-file CFG, MEM30, MEM31 | + | S |
| MEM31-C `statement_cannot_fall_through` `None => own` (4706), `visit_preproc_chain` (2382) | A lone #ifdef arm with no #else is assumed compiled. `#ifdef DEBUG return; #endif` hides a double free (reproduced by the auditor). | MEM31 | + | C |
| MEM31-C `analyze_node`/`visit` (1662, 1831) | State leaks out of `#if 0`: `#if 0 free(p); #endif free(p);` reports a double free (reproduced). | MEM31 | - | C |
| MEM30-C `uaf` (5146), `mark_arg_freed` (3957) via `preproc_conditional_between` (5398) | Any #if/#ifdef/#else/#endif line between free and use drops the finding, even a self-contained `#ifdef DEBUG log(); #endif`. | MEM30 | + | C |
| EXP33 `enclosing_ifdef_guard_key` (530), `has_macro_shadow_definition` (678) | Only the nearest #ifdef is compared, and any `#define var` in the body suppresses. | EXP33 | + | C |
| API00 `check_validation_patterns` (810) | Descends into #ifdef/#else, so a NULL check in one arm validates every configuration. | API00 | + | C |
| FIO22 `process_statement` (139-205) | `preproc_if`/`preproc_ifdef` fall to `_ => {}`, so every open, close and spawn inside a #if arm in a function body is invisible, including the usual `#ifndef _WIN32 ... fork()`. | FIO22 | + | C |
| FIO24 `check_close_call`/`check_fopen_call` (330/280); FIO46 (70-170); FIO01 `check_scope` (105-180); FIO13, FIO50, FIO45 sequencing; POS53, POS51 | Operations are sequenced in source order by argument text, so exclusive arms (and if/else) merge. Example: `#ifdef _WIN32 closesocket(s); #else close(s); #endif` is reported as a double close. `PreprocArms::exclusive` is the fix. | FIO24/46/01/13/50/45, POS53/51 | - | C |
| DCL36 `get_linkage` (51-62); DCL40 `check_node` (400-446); DCL07 `find_declaration_params` (183) | Declarations from all arms go into one name map (`#ifdef _WIN32 int f(HANDLE); #else int f(int);` is reported as "incompatible"). DCL36 also treats `extern` as Internal. | DCL36, DCL40, DCL07 | - | C |
| MSC13 `build_decl_start_to_group` (129), `macro_hides_use` (518); MSC37 `collect_returning_macros` (92) | A read in arm A credits arm B's declaration. A `return` in any arm, even a conditional one, makes the macro a path end. | MSC13, MSC37 | + | S / C |
| PRE31 `is_safe_macro_definition` (~205), `scan`/`check_macro_call` (78/122); PRE13 `check_node` (~200) | PRE31 checks only the first arm, and its "rest of the source" window runs to the end of the file. PRE13 pushes `defined(X)` into the #else arm. | PRE31, PRE13 | + | C |
| DCL39 `find_safe_struct_types` (124) | Also 0011 b4: `__attribute__((packed))`/`#pragma pack` count as proof, `contains("padding")` too, and an `_MSC_VER`-only pack arm is credited. | DCL39 | + | C |
| EXP34 `assert_condition` (1804): the `ALWAYS` half | A statement-level `ALWAYS(p)` is credited as non-null. ALWAYS is (1) under SQLITE_OMIT_AUXILIARY_SAFETY_CHECKS. Handled together with the assert half, since it is the same function. | EXP34 | + | C |

### A4. Project-wide maps looked up by name (ADR-0006: a name is not a variable; a tag is not a type)

| where | shortcut | consumers | dir | conf |
|---|---|---|---|---|
| prescan.rs 661/663 `struct_field_types`/`typedef_types` `.extend` | A whole-struct, last-file-wins merge, and these rules read it without the file-first overlay that INT02 and ARR36 have. MEM31's case was reproduced by the auditor. | EXP14 (`field_type_text`/`width_of_type_text`), EXP36, EXP10, API00, MEM31 (`collect_value_only_fields`, `resolve_macro_based_field_type`), INT10, INT16 (`set_project_context` 98), INT30, INT31, INT32, INT33 (`register_typedef_aliases`), DCL05 `pointer_typedef_names` | both | C (EXP14, EXP36, INT16, MEM31), S (rest) |
| prescan.rs 667 `noreturn_functions.extend` | A by-name union that includes inferred **static** fns, so file A's `static void fatal(){exit(1);}` makes file B's returning `fatal()` noreturn (reproduced in MEM31). | MEM30, MEM31, abort_check_macros (check_macros) | + | C |
| prescan.rs 675 `global_var_null_states.extend` | The doc says "joined across all files", but the code does a last-file-wins extend by bare name. | EXP34 extern globals | both | C |
| overflow_helpers `collect_variable_types` (94); float_typing `collect_variable_types` (180); pointer_typing `expr_is_pointer` (140) | A flat per-function name→type map, file-wide when handed the TU root (API00:159, INT10:136, INT30/32 fallbacks). `expr_is_pointer` resolves the declarator and then lets the map win over it. | API00, INT00/02/08/10/30-33, FLP06/34, ARR36, MSC | both | C |
| dataflow.rs `Definition{variable: String}` / `compute_reaching_definitions` | Reaching definitions are keyed by name, so a shadowing inner x and the outer x are one variable. | MSC13, MEM30, MEM31 | both | C (shape) |
| variable_analysis.rs (all 4 pub fns); size_analysis.rs (`find_element_size`, `find_string_literal_length`, `find_allocation_size`) | Text scans such as `preceding_text.contains(&format!("&{}", var))` and `format!("{} =", var)` with no word boundary. | ARR00, ARR38 | both | C |
| buffer_size.rs `resolve_strlen_based_alloc_size` (562) | Any line in the function (not the reaching definition) with `var = malloc(strlen(..)+1)` returns usize::MAX ("safe"). | STR31, function_summary | + | C |
| ast_utils `is_likely_macro_constant` (2222) | Any ALL_CAPS name is taken to be a constant. | ARR32 and others | + | C |
| null_state `collect_param_pointer_state` (2018) | Pointer-ness from spelling: `name.contains("callback")`, `param_text.starts_with("FILE")`. | EXP34 | ~0 | C (low impact) |

### A5. Inference credited as proof (ADR-0011 b3/b5, "a prior dereference is not a check", name lists)

| where | shortcut | consumers | dir | conf |
|---|---|---|---|---|
| guard_dominance `preceding_if_conditions` / `has_dominating_limit_guard` / `is_integer_limit_name` (666/1081/1057) | Any evaluated comparison counts: the preceding `if` need not exit, and branch direction isn't checked. Any `*_MAX`/`*_MIN` name (e.g. BUF_MAX) counts as a type limit. | API00, ARR30, ARR38, INT30, INT32 | + | S |
| null_state.rs ~1828 → guard_dominance `has_dominating_dereference` (the only caller) | A disjunctive null edge (`if (p && ...)`) is discarded because `p->x` came earlier. That earlier dereference is usually of a parameter seeded NotNull, so it is never reported itself. This is not assert-related; The assert change covers only dereferences inside an assert. | EXP34 and other null_state users | + | C (behavior), P (the "first site" reading) |
| function_summary `check_never_returns` (1629) | Text-only: no `"return "` in the body plus `contains("exit(1)"/"abort()")` anywhere gives never_returns. A void `if (e) exit(1); work();` qualifies, and so does `txn_abort()`. | ERR33 `is_safe_wrapper_function` (which also has its own `x`/`safe_`/`_or_die` name list) | + | C |
| init_state `INITIALIZER_SUFFIXES` (218), `match_initializing_function`, `process_unknown_function_call` (1589) | The `*_memset`/`*_strcpy` suffix match runs before the cross-file summary. POSIX read/recv/stat/getaddrinfo count as initializing unconditionally, and so does any unknown callee taking `&var`. | EXP33 (`is_read_in_argument_list` 1927, `check_identifier_read` 975: array → unknown callee counts as initialized), function_summary `library_written_roots` | + | C (order), S (impact) |
| ast_utils `documented_nonnull_parameters` (1200) | A doc comment saying "must not be NULL" exempts the parameter. That is an internal contract, weaker than a `nonnull` attribute, which ADR-0011 already rejects. The code comment says this was deliberate. | API00, EXP34 | + | P |
| int_provenance `operand_is_risky` (116-176), the opt-in taint gate | Fields, subscripts and untainted locals count as "bounded local state... practically non-overflowing" (`_ => false`). This is suppression by inference; ADR-0001 says it belongs in config. | INT30/31/32, FLP03 | + (large) | P |
| noreturn.rs `NORETURN_ATTRIBUTE_MACRO_NAMES = ["NORETURN"]` (60) + `__attribute__((noreturn))`/`_Noreturn` credit | A name list, and the attribute is compiler-level: a returning noreturn function is UB, not impossible. Under ADR-0011 b4 this is treated like nonnull, unless `_Noreturn` (C11 keyword, 6.7.4) is ruled basis 1. | CFG rules, MEM30, MEM31, check_macros | + | P |
| null_state `is_nullable_function` (2074) vs dataflow `is_nullable_function` (500) | Two diverging name lists. One includes `"create_int"`, a Juliet leftover. They only add findings. | EXP34, dataflow users | - | C (low) |
| function_summary `is_allocator_name` (1412); argument_objects `allocation_object` (358) | `contains("malloc")`; `os_` prefix stripping (hostap-specific). | MEM rules | both | S |

---

## B. Rule-local rows, by family

These are mostly misfire generators (ADR-0005 via 0006) or single-rule suppressions. Each is small unless marked otherwise, and all are "new" unless a covering task is named.

### EXP
| where | ADR | shortcut | dir | conf |
|---|---|---|---|---|
| EXP34 `is_dominated_by_null_check` / `has_dominating_null_check` (1274-1335) **[V]** | 0011 b5 | Any earlier `if (p == NULL) {...}` before the dereference in byte order clears it, whether or not the branch exits and with no reassignment check. The code says: "programmer assumes error was handled". | + | C |
| EXP34 `is_guarded_by_rc_success` (1337-1555) | 0011 b4/5, 0005 | `rc == SQLITE_OK` plus `&p` passed to the call makes p non-null for any callee, without consulting it. sqlite3_prepare itself returns SQLITE_OK with `*ppStmt = NULL` on empty SQL. The fix needs a summary fact, "out-param non-null on success". | + | C |
| EXP34 `is_sqlite_null_safe_api` (888) | 0011 name list | sqlite3_column_*/bind_*/step/mprintf are NULL-tolerant by name in every corpus. | + | S |
| EXP34 → macro_semantics `is_in_iterator_macro_body` | 0005 | A fixed name table (LL_FOREACH, TAILQ_FOREACH, ...) instead of macro_expand. | both | S |
| EXP37 `check_node` (43-48) | 0006 | `lines_before.contains("complex") && contains("=")` searches the whole earlier file, comments included. Same shape as the old INT02 bug. | - | C |
| EXP40 `find_const_ptr_ptr_decl` (310), `contains_const_keyword` (433) | 0006 | Any declaration in the file containing "const", "**" and the name as a substring. Same shape as the old EXP05 bug. | - | C |
| EXP39 `infer_type_from_name` (844), `check_realloc_cast` (559) | 0006 | Identifiers starting with 'f' are float; `ch` is char. `source_after.contains("memset(p")` searches the rest of the file. | - / + | C |
| EXP08 `looks_like_struct_pointer`/`looks_like_offset_value` (216-250) | 0006 | Any single-letter identifier is a struct pointer; any name containing "offset" is a byte offset. | - | C |
| EXP43 `find_restrict_declarations`/`track_pointer_assignment` (259-340) | 0006 | `contains("restrict")`, and a function-wide alias map with no flow. | - | C |
| EXP16 `is_function_identifier` (363); EXP11 `collect_bitfield_variables` (145) | 0006 | File-wide name sets, so shadowing locals misfire. | - | C |
| EXP33 `check_deref_read` (1195), `check_subscript_read` (1300); `conditional_output_is_return_guarded` (1089); `collect_param_list_with_indices` (2231) | 0006 / 0011 b5 | Declarators aren't resolved, unlike `check_identifier_read`. Any dominating condition mentioning the result counts, in either polarity. Pointer-ness is taken from `contains('*')`. | both | C |

### MEM
| where | ADR | shortcut | dir | conf |
|---|---|---|---|---|
| MEM31 `process_custom_deallocator` (3634, 3708) | 0011 name list | `contains("safe")`, `destroy_*` or `*_destroy` suppresses a double free even when the summary proves the parameter is freed. | + | C |
| MEM31 `is_allocation_call` (4497) | 0005 | The name-prefix allocator heuristic (create_/new_/_dup/build_) runs before `summary.returns_allocation`. | - | C |
| MEM31 `check_for_return_macro` (1063) | 0005 | Any callee whose name contains RETURN, EXIT or ABORT reports every live allocation. Reproduced on `atexit(0)`. | - | C |
| MEM31 `is_this_function_owned_field_target` (2995); `track_allocation_guarded` (1412) | 0006 | Globals count as owned locals. A project-wide `value_only_globals.contains(name)` silences a shadowing local. | both | C |
| MEM30 `LValue::Var` freed state (4613), `union_typed_vars` (1962); `arg_can_be_freed` (3824); GlobalTracker `scan_call_expression` (898) / `scan_identifier_access` (957) | 0006 | Scope-flat freed state, the summaries lookup before identifier resolution, and bare `global_vars.contains(name)`. | both | C |
| MEM30 `is_all_caps_or_literal_constant` (1672) | 0006 / 0011 b4 | ALL_CAPS names are taken as distinct constants, so EAGAIN and EWOULDBLOCK count as disjoint and frees are dropped. | + | C |
| MEM30 `process_call_expression` (3563) etc.; `check_field_access` (5054) | 0005 | `upper_name.contains("REALLOC"/"FREE")` is checked before the summary. | both | C |
| MEM33 flexible-array detection (1388-1568, 967, 173), `trace_variable_definition` (2457) | 0006 | `var_name.contains("flex")`, file-wide name sets, and `_ptr`/`alloc`/`data`/`buffer` suppressions. | both | C (medium) |
| MEM04 `has_preceding_zero_check` (261) | 0006 / 0011 b3 | A 50-line text window with a substring name. | + | C |
| MEM03 `scan_sensitive_vars_and_clears` (463) | 0006 | `decl_text.contains('*')` includes the initializer, so `size_t password_len = n * 2;` becomes a "sensitive buffer". | - | C |
| MEM02 `collect_var_types` (104) | 0006 | Function-wide name→type map. | - | C (low) |

### INT / FLP
| where | ADR | shortcut | dir | conf |
|---|---|---|---|---|
| INT00 `find_type_in_source` (338) | 0006 | `normalized_source.contains("long {var};")`, the textbook case. | both | C |
| INT00 `has_subtraction_guard` (601); INT16 `has_non_negative_guard` (702); INT08 `has_overflow_protection` (554/616); INT04 `collect_validations` (230); INT31 `collect_if_bounds_validation` (976), `is_inside_bounds_checked_block` (1789), `is_inside_non_negative_guard` (1876); INT32 `has_function_level_overflow_check_scoped` (3514); INT33 `is_struct_field_validated` (1637), `checks_for_zero` (922), `has_early_return_for_zero` (812), `is_in_safe_branch` (898); INT34 `checks_shift_bounds` (1022), `is_in_safe_branch` (1117); INT30 `has_function_context_check`/`has_preceding_overflow_check`/`has_postcondition_check`/`has_shift_overflow_check`/`uses_wider_type` (2529-2700); FLP03 `is_inside_division_guard` (459); FLP04 `has_validation_check` (143); FLP34 `has_range_checking` (283); FLP36 `has_precision_checking` (non-assert part) | 0006 / 0011 b3 | Guards credited by text co-occurrence: a substring name plus any comparison or limit macro, in any arm, not dominating, sometimes after the operation. **One class; suggest one task per rule family.** | + (large in aggregate) | C |
| INT01 `find_size_t_vars`/`find_int_vars` (107/126); INT08 and INT13 `parse_declaration` (125/96); INT10 `looks_unsigned` (406), `is_in_function_with_unsigned_params` (425), `operand_has_unsigned_type` (303); INT12 `check_field_declaration` (73); INT14 `collect_params_from_list` (111); INT15 `check_printf_cast` (174); INT18 `is_larger_type_variable`/`is_unsigned_variable`/`param_has_larger_type`; INT30 `infer_type` (1709), `is_variable_declared_unsigned` (1833); INT31 `is_signed_type`/`is_unsigned_type`/`is_narrow_type`/`is_wide_type` (2254-2323); INT32 `infer_type_from_identifier_name` (2434), `find_variable_declaration` (2461), `could_be_int_min` (2828); INT33 `extract_base_variable` (789), `find_zero_initialized_vars` (173); INT36 `check_pointer_to_integer_cast` (84); INT07 `is_plain_char_declaration` (172); overflow_helpers `is_short_unsigned_typedef` (460) | 0006 | Type or signedness decided from spelling or declaration text, e.g. `contains("size_t")` matches ssize_t, a name starting with 'u' is unsigned, `contains("ptr")` is a pointer. **One class; suggest one task per rule family.** | both | C (INT07 S) |
| INT30 `check_subtraction` (665), `check_increment_decrement` (1219), `is_small_increment_of_opaque` (1864); INT32 `is_small_increment_of_opaque` (3012); INT30 `is_elapsed_time_subtraction` (2090) | 0011 b5 / name list | "practically never wraps" / unknown callee with k ≤ 10 is suppressed; Tick/Time/Clock in a name suppresses. | + | C |
| INT34 `shift_amount_bounded_by_modulo` (419), `mask_bounds_shift_amount` (355); INT31 `rhs_has_safe_mask` (2188) | 0011 b3 | `% N` with N ≤ 64 or `& M` with M ≤ 63 is accepted without comparing to the operand width. | + | C / S |
| FLP02 `collect_float_variables` (150); FLP03 `collect_float_vars` (93), `contains_fp_error_checking` (185); FLP07 `find_long_double_decl` (104); FLP36 `is_long_variable` (106) | 0006 | File-wide float name sets (initializer identifiers included), and `contains("_except"/"_try")` on every node. | both | C |

### ARR / STR / API
| where | ADR | shortcut | dir | conf |
|---|---|---|---|---|
| API00 `is_static_function` (1651); DCL15 `has_static_macro_in_prefix` (200); DCL19 `STATIC_MACROS` (153); ARR30/ARR00 same helper | 0010 / 0011 name list | Any prefix containing `STATIC`, or `PRIVATE`/`INTERNAL`/`LOCAL`, counts as static. mbedtls `MBEDTLS_STATIC_TESTABLE` expands to nothing under MBEDTLS_TEST_HOOKS (library/common.h:63), so those functions are external in that configuration. macro_expand should decide it. | + | C |
| API00 `extract_validated_params_from_condition` (1040), `check_return_statement_validation` (972) | 0006 | `format!("!{}", param)` substring matching, so parameter `s` is "validated" by `!strcmp(...)`. `condition_tests_null` exists. | + | C |
| API00 `is_callback_context_parameter` (1860), `is_debug_parameter` (1850), `is_comparator` (243) | 0011 b5 idiom | Parameters named priv/opaque/userdata/file/line are never checked; hostap driver ops dereference `void *priv`. | + | C |
| API00 `is_null_accepting_stdlib` (1436) | 0011 b4 / 0005 | `cfree`, `Memory_Free` and `dbus_set_error*` are NULL-safe by name, not ISO. | + | C |
| API00 `has_unchecked_arithmetic` (428-495) | 0011 b5 | A comment containing "will overflow" exempts the function; Tick/Time in the body counts as intentional wraparound. | + | C |
| ARR30 `TERMINATING_BOUNDED_WRITES` (7993) | 0011 b4 | `("strlcpy", 2)` credited as always terminating, by name. It is not ISO C. | + | C |
| ARR30 `check_if_bounds_against_size` (2151), `has_function_parameter_bounds_check` (1765), `pointer_walk_is_bounded` (~4725), `get_array_name_from_subscript` (1078) → `buffer_in_scope_at` (1147) | 0006 / 0011 b3 | `contains("< 10")` matches `< 100`; any `if` mentioning the parameter counts as its bound; `'>'` matches `->`; `s.buf[i]` is sized by member name file-wide. | both | C (medium) |
| ARR32 `has_prior_validation` (274), `has_nearby_bounds_check` (213) | 0006 | A VLA size `n` counts as validated by `if (len < x)`. | + | C |
| ARR38 `is_type_size_mismatch` (2848); ARR39 `looks_like_pointer` (527), `is_scaled_integer_expression` (499), `is_byte_type` (640); ARR01 `is_typedef_array_parameter` (286), `is_flexible_access` (733); ARR00 `find_array_size` (2430), `check_vla_size_validation` (407), `check_use_after_free` (1700), `is_loop_variable` (453), `find_pointer_source_array` (2276), `param_is_array_for` (~2600: `int a[]` parameter treated as an array, but C11 6.7.6.3p7 makes it a pointer) | 0006 | Spelling-based type, identity and size. | both | C |
| STR02 `check_exec_family_call` (998); STR03 `find_length_check_in_scope`/`is_length_validation` (150-197) | 0006 | `scope_text.contains("strspn(")` counts as sanitization; any earlier `if` with strlen and `<` counts as the guard. | + | C |
| STR31 `check_strcpy_known_buffer_size` (963), `check_strcat_safety` (~1175), `check_sprintf_safety` (~1340), `check_strcpy_source_variable_safety` (1073); plus `find_define_constant` (150), `find_array_declaration_size` (240), `is_function_parameter` (1404), `traces_to_argv` (1382), `is_variable_from_getenv` (1120), `has_prior_safe_realloc` (813) | 0011 b5 / 0006 | A buffer of 256 or more is "safe for typical usage"; a source of 3 characters or fewer is always safe; a name containing hello/world is known safe. Whole-file `line.contains(var)` scans. | both | C (rewrite-sized) |
| STR38 `collect_var_types`/`check_calls` (64-200); STR09 `collect_char_vars` (65); STR30 `StringLiteralAnalyzer` (47-95), `is_function_returning_literal` (338), `check_unknown_function_literal_arg` (563); STR06 `collect_getenv_vars` (115); STR04 `find_variable_type` (134); STR34 `check_translation_unit` (60); STR00 `check` (104) | 0006 | File-wide name maps. STR38 also iterates a HashMap, so its output is **nondeterministic**. STR30 reports `curl_easy_setopt` as "may modify" because the name contains "set". | - | C (STR00 S) |
| API07 `is_pointer_modification` (414), `check_type_confusion` | 0006 / 0011 b4 | `"{var}++"` matches `cp++`; a text type map with int = 4 and long = 8. | - | C |

### DCL / FIO / POS / ENV / SIG / ERR
| where | ADR | shortcut | dir | conf |
|---|---|---|---|---|
| FIO05 `process_open_call_with_var`/`process_close_call`/`check_attribute_comparison` (318/368/427) | 0006 | Keyed by filename text; fd/FILE* identity by text equality; `contains("st_dev")` matches `first_dev`. An `fd = fopen(..)` is recorded twice, and the `fd_var=None` copy can report even when `fstat(fd)` exists (a misfire). **This is the named suspect.** | both | C (medium) |
| FIO08 `analyze_file_operations` (57-110) | 0006 / 0005 | A TU-wide set of open files keyed by filename text; fclose never removes an entry ("simplified here"). | - | C |
| FIO02 `check_node`/`is_canonicalized_var` (82/389) | 0006 | TU-wide tainted names; `arg_text.contains(var)`, so canonicalizing `p` clears any argument containing a "p". | both | C |
| FIO30 `could_be_user_input` (1325) | 0006 / name list | Names containing user/input/cmd/format are tainted; CONST_STYLE names are safe. | both | C |
| FIO18 `collect_strlen_assignments` (73); FIO44 `track_fpos_vars` (50); FIO42 `analyze_function` | 0006 | TU-wide name sets. | both | C (FIO42 S) |
| DCL30 `is_local_variable` → `contains_identifier_by_name` (725-801) | 0006 / 0005 | `char *q = p; return p;` reports "returns pointer to local 'p'". | - | C |
| DCL00 `has_const_qualifier`/`should_be_const` (113-218); DCL13 `is_likely_readonly_param` (205), `READ_ONLY_FUNCTIONS` (326: lists stat/lstat, whose 2nd argument is an output); DCL17 (148); DCL08 (127); DCL05 (93); DCL31 (199) | 0006 / name list | Substring qualifiers and types; parameter-name heuristics; file-wide name sets; project typedef set unioned so the file's own doesn't win. | both | C |
| DCL19 `check_file_scope_variable` (238) | 0011 b5 | Every file-scope volatile skipped as "typically ISR-shared". | + | C |
| POS54 `check_node`/`statement_checks_error` (~100/223) | 0006 / 0005 | For `FILE *fp = fmemopen(..)` the recorded name is `*fp`, so `if (fp == NULL)` is never recognized (misfire). | - | C |
| POS34/38/39/48/49/50 (see the report for lines) | 0006 | Substring declaration and fd lookups (fd `f` matches inside `printf`; `&id` inside `&idx`; POS50 takes a static as automatic). | both | C |
| ENV30 `is_safe_function` (616) | 0011 name list | A callee containing copy/dup/_safe is assumed not to modify argument 1; the parameter's const should decide. | both | C |
| ENV03 `check_for_sanitization` (249) | 0011 b3 | clearenv/setenv anywhere in the function counts, even after the call. | + | S |
| SIG30 `ASYNC_SAFE_FUNCTIONS` (~290) | 0011 (beyond POSIX) | `execvp` listed as async-signal-safe; POSIX does not list it. | + | C |
| SIG31 `find_global_variables` (188) | 0011 b4 / 0006 | Any `atomic_*` counts as safe with no lock-free proof; parameters shadowing globals are reported. | both | C |
| SIG35 `check_handler_for_return` (~318) | 0011 b5 | A termination call anywhere in the handler with no `return` counts as compliant. | both | C |
| SIG02 `check_complex_handler` (225); ERR32 `is_in_signal_handler` (145), `has_errno_save_restore` (101) | name list | Handlers by wu-ftpd example names, or a name containing "handler" or starting with "sig"; save/restore only when named `saved_errno`. | - | C |
| ERR30 `check_errno_in_if` (85); ERR33 `find_error_check_in_context` (1215), `is_in_error_handling_context` (1454); ERR00 (179), ERR02 (41/61) | 0006 / 0011 b5 | `contains("errno")` matches errnum; `"!{var}"` substring; function names or nearby text containing "cleanup" credited. | both | C (ERR00/02 S) |

### MSC / PRE / CON / WIN
| where | ADR | shortcut | dir | conf |
|---|---|---|---|---|
| CON03 `collect_accessing_functions` (194), `has_atomic_type` (305), `is_synchronization_type` (321) | 0006 | Accessors are matched by text (CON07 already uses `resolve_identifier_binding`); `text.contains("atomic_")` or `"sem_t"` on the whole declaration, so `static int sem_total;` counts as a sync object. | both | C |
| CON03 volatile counted as synchronization (145) | 0011 b4 | C11 volatile gives no inter-thread ordering; CON02 in the same repo says so. | + | P |
| CON07 `check_function_for_non_atomic_operations` (281) **[V]** | 0011 b5 | `func_name.to_lowercase().contains("init")` skips the function. | + | C |
| CON07/08/09/32/43 `uses_mutex_lock`/`has_mutex_lock`/`has_synchronization_nearby` | 0011 / 0006 | Any lock call anywhere in the function exempts the whole function; never checks the access is in the critical section or which mutex. Needs a lock-region primitive. | + | C |
| CON02 `looks_like_synchronization_flag` (236) **[V]** | 0005 / 0006 | A non-volatile global is reported as "used for synchronization" because its name contains flag/done/stop/active; a non-volatile variable cannot violate CON02 (misfire). | - | C |
| CON31 `is_thread_function` (81); CON32 `collect_bitfield_accesses` (361), `is_potential_thread_function` (299); CON35 `has_conditional_lock_order` (140); CON34 `is_likely_allocated_param`; CON39 `search_for_thread_create`; CON04 `check` (70); CON40 (104-240); CON06; CON08 (160) / CON09 `has_hazard_pointer_protection`; CON43 `check_static_volatile`; CON37 `has_threading_functions` | 0006 / 0011 b5 / 0005 | Thread functions by name (anything without "main" is a thread); a lock-order proof from argument text such as first/second; identity by text. `concurrency_roots` exists and is not used. | both | C (CON37 S) |
| MSC13 `collect_single_invocation_locals` (160); MSC12 `mentions_volatile_operand` (867); MSC40 `find_static_references` (297); MSC22 `reassigned_outside` (145); MSC06 `check_unsafe_clear` (51) | 0006 | Name-set scope, and storage duration never resolved. MSC40 also flags `static const`, which C11 6.7.4p3 allows. | - | C |
| MSC13 `collect_unused_annotated_decls` (268) | 0011 b4/5 | `__attribute__((unused))` silences a variable that really is unused. The context doc calls this deliberate. | + | P |
| PRE31 `is_unsafe_macro` (~170), `is_volatile_variable_access` (~470), pure-function list (~330); PRE05 `has_proper_wrapper`/`is_likely_helper_macro`; PRE32 `is_potentially_macro_function` (~660) | 0005 / 0006 | Any ALL_CAPS name is a macro; `abs` and `putc` are listed despite C 7.1.4; math functions count as pure though they set errno; `CAT` matches `CATEGORY(` (the real `called_macros` is computed and unused). | both | C (PRE32 S) |
| WIN30 `check`; WIN00 `flags_provably_lack_search_path` (~25); WIN03 `check_handle_from_cmdline` (~211) | 0006 / 0005 | Any FormatMessage in the file makes every GlobalFree a FormatMessage free; any ALL_CAPS macro is taken to lack the flag. | - | C |

---

## C. Rulings needed before fixing (maintainer)

1. **Widths (A2).** Does the tool pin a data model per corpus (the earlier design note's proposal) or stop suppressing on width? The earlier "int is 32-bit, correct" framing predates ADR-0011 basis 4.
2. **`_Noreturn` / `__attribute__((noreturn))` as proof (A5).** `_Noreturn` is a C11 keyword and arguably basis 1; the GNU attribute is basis 4 like nonnull. This also affects check_macros.
3. **Doc-comment non-NULL contracts (A5)**, `documented_nonnull_parameters` in API00 and EXP34: an internal contract, deliberately credited.
4. **int_provenance's opt-in taint gate (A5)**: suppression by inference, or config under ADR-0001?
5. **`has_dominating_dereference` (A5)**: is dropping the later `if (p && ...)` disjunct the "first site of failure" principle, or a prior dereference credited as a check?
6. **Attribute-unused (MSC13) and volatile-as-sync (CON03)**: deliberate or basis 4?
7. **EXP34 `assert_condition`'s ALWAYS half (A3)**: decided: handled with the assert change.

## D. Outside these ADRs (for completeness)

- **ADR-0001:** PRE08 `VENDOR_SDK_PREFIXES` is an in-rule suppression by vendor name.
- **ADR-0001:** ERR33 hard-suppresses ignored printf/puts results and `signal(..., SIG_IGN)`.
- **MEM31:** once any `signal()` has been seen, every later allocation gets "may leak if handler terminates", with no path scoping.
- **Determinism:** STR38's HashMap iteration makes its output nondeterministic.
- **Not audited in depth:** DCL02/03/04/09/10/11/12/16/18/20/21/23/37/38/41/42; float_typing, format_slots, fn_ptr_bindings, loop_consumption, clearing_extent, declarator_utils, points_to; the preprocessor-repair passes.

## E. Checked and conforming (coverage evidence, abbreviated)

- **Suppression and platform profile:** suppression.rs uses only the unseeded dead_code_ranges. dead_regions' platform profile only resolves names; no rule in any slice filters findings by it or by `_WIN32`/`_MSC_VER`.
- **Linkage and file-first overlays done right:**
  - `seedable_param_states` and `callsite_param_proven_nonnull` are gated on linkage and address-taken, as is EXP34's `collect_proven_nonnull_params`.
  - `merged_macro_constants` and `merged_macro_aliases` let the file's own definitions win.
  - INT02 and ARR36 apply the file-first struct/typedef overlay.
- **Declaration resolution in place:**
  - INT02 resolves operands.
  - FIO47 (its type-resolution fix holds) and FIO34 resolve types.
  - ENV34/ENV30 variables, MSC05/15 and CON07 `StaticVars::resolves` use the resolver.
  - ARR30 resolves plain identifiers.
  - MEM31 loop-array ownership resolves bindings.
- **#if arms as alternatives:** cfg.rs models arms as alternatives; ARR36's per-arm fix holds; MEM31 walks multi-arm chains as alternatives.
- **Function summaries:** `merge_summary_variant` unions MAY facts and intersects MUST facts. `ScopedTable` lets a file's own static win.
- **API00:** no longer uses the caller vote, doesn't credit dispatch-table callbacks, and has no assert-as-validation.
- **ISO or POSIX lists used as specified:** noreturn stdlib (abort, exit, _Exit, quick_exit, longjmp), CON33/38/41, FIO31/32/38-41/51, `call_roles`.
- **Proofs that are real:** INT33 `divisor_provably_nonzero` (VRA), `has_dominating_limit_guard`'s VRA path, FLP03 `divisor_provably_nonzero_fp`, INT34 `is_platform_width_long`, INT30 `calloc_args_are_function_params` (C11 7.22.3.2).

## F. Suggested order

1. **A1 linkage gates.** The pattern exists (`has_internal_linkage && !address_taken`), some already tracked. New: int_args, including the per-file path; buf/field/taint args; FIO30; concurrency reachability.
2. **A3 shared config primitives.** Constant folding plus first-wins macros, `collect_file_scope_constants`, `BLOCK_LIKE_KINDS`.
3. **A4 file-first overlay.** One shared overlay for struct_field_types/typedef_types, then the static-noreturn union.
4. **EXP34 rule-local proofs.** `is_dominated_by_null_check` and `rc_success`: EXP34 is paper-central.
5. **The rulings in C.**
6. **Rule-local 0006 misfire generators, by family.** Largest volume but lowest per-item leverage. Suggest one task per family with this table's rows as its checklist.
