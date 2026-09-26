//! Function summary computation for inter-procedural analysis.
//!
//! Computes lightweight summaries of each function's behavior during the prescan
//! phase. These summaries are used by rules to reason about callee behavior
//! without re-analyzing the callee's body.

use crate::analyze::const_eval::{self, MacroConstantMap, ValueRange, VarRangeMap};
use crate::analyze::init_state;
use crate::analyze::null_state::NullState;
use crate::utility::cert_c::guard_dominance;
use std::collections::{BTreeSet, HashMap, HashSet};
use tree_sitter::Node;

/// Summary of a function's behavior relevant to CERT C rules.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FunctionSummary {
    /// Parameter indices that this function frees (e.g., free(param\[0\])).
    /// This is a MAY-free fact: the free can be nested inside a conditional
    /// (if/switch/loop/ternary), so it does not mean every call reaches it.
    pub frees_params: HashSet<usize>,
    /// Parameters this function hands, as the one parameter-naming argument,
    /// to a callee whose NAME is shaped like a deallocator (`free_*`,
    /// `*_cleanup`, ...): `(callee, position of the argument in that call,
    /// whether the call site is unconditionally reached)`.
    ///
    /// Held apart from `frees_params` while a file is summarised, and folded
    /// in by `resolve_name_shaped_frees` once every summary exists, so the
    /// fold can also record in `frees_params_guessed` that a name was the
    /// only evidence.
    #[serde(default)]
    pub frees_params_by_name: HashMap<usize, Vec<(String, usize, bool)>>,
    /// The subset of `frees_params` whose only evidence is a callee's NAME --
    /// no body of this function, or of anything it forwards the parameter
    /// to, was seen to release it.
    ///
    /// A name is a MAY-free at best. It is enough to stop a leak report,
    /// which is what the guess is for, and it is what makes `sqlite3_free`
    /// -- whose body frees through the `xFree` function pointer the prescan
    /// cannot follow -- still count as a free. It is not enough to ACCUSE: a
    /// later `free(p)` after `x_cleanup(p)` is a teardown pair unless
    /// `x_cleanup` was seen to free `p`. curl's `Curl_req_free(&data->req,
    /// data)` was summarised as freeing `data` because it calls
    /// `Curl_client_cleanup(data)`, and hostap's `wpa_supplicant_cleanup`
    /// because it calls `free_hw_features(wpa_s)` (which frees fields of it),
    /// so the owner's one real free at the end of `Curl_close` /
    /// `wpa_supplicant_deinit_iface` was a double free. MEM31-C
    /// reads this to keep such a credit in `freed_by_guess`, where
    /// `guess_forbids_double_free` already knows what to do with it. MEM30-C
    /// reads it to mark a use-after-free that rests on such a credit
    /// `requires_manual_review`: the finding stands -- for a wrapper whose
    /// body frees through a function pointer the name is the only evidence
    /// there will be -- but the reader is told the free is an inference
    /// . A guess the callee's own body CONTRADICTS never gets
    /// here at all; see `resolve_name_shaped_frees`.
    ///
    /// Cleared for an index the moment real evidence arrives -- a literal
    /// free in this body, or a forwarding to a callee whose own free of it
    /// is not itself a guess.
    #[serde(default)]
    pub frees_params_guessed: HashSet<usize>,
    /// Parameter indices that this function UNCONDITIONALLY frees — the free
    /// is not nested inside any conditional construct other than a null test
    /// on the very pointer being freed (`if (p != NULL) free(p);`, whose
    /// skipped path has nothing to free and so leaves nothing for a caller to
    /// use), so it executes
    /// whenever the function itself is entered (modulo an early return
    /// before it, which the AST-position check already accounts for since
    /// it only asks "is this call inside a conditional", not "could an
    /// earlier statement return first"). Subset of `frees_params`. This is
    /// the MUST-free fact rules like MEM30-C need to safely mark an argument
    /// as definitely freed after a call — trusting the MAY-free set for that
    /// purpose caused cascading false UAF/double-free reports when a helper
    /// only frees its argument on an error path a given caller didn't take
    /// .
    #[serde(default)]
    pub unconditional_frees_params: HashSet<usize>,
    /// For each index in `frees_params`, the preprocessor-arm assumptions of
    /// every definition that frees it
    /// ([`crate::analyze::dead_regions::arm_assumptions`]); an empty entry is
    /// a definition no arm constrains. A caller applies a free only when one
    /// of those definitions can compile together with the call
    /// ([`Self::frees_at`], [`Self::unconditional_frees_at`]). An index with
    /// no entry here came from a later pass (name folding, transitive frees)
    /// and applies everywhere, as before.
    #[serde(default)]
    pub free_arms: HashMap<usize, Vec<Vec<(String, bool)>>>,
    /// Subset of `modifies_params` whose write through the parameter is not
    /// known to be conditional — the MUST-write fact, and the output-param
    /// counterpart of `unconditional_frees_params`.
    ///
    /// A rule that clears an "uninitialised" state because a callee writes
    /// through an output parameter needs MUST, not MAY. `set_flag(n, &sign)`
    /// writes `*sign_flag` under `if (n > 0)` and `else if (n < 0)` and writes
    /// nothing when `n == 0`, so the caller can still read `sign`
    /// uninitialised — the CERT wiki's own noncompliant example, which
    /// EXP33-C missed for as long as MAY was all the summary offered
    /// .
    ///
    /// Built by DEMOTION rather than by re-derivation: a parameter leaves the
    /// set only when the AST pass found writes through it and every one of
    /// them was conditional. A parameter whose writes the pass cannot see —
    /// through a macro, or a nested helper — stays in, so the narrower AST
    /// view can only act on positive evidence and never silently withdraws a
    /// write the text scan did find.
    #[serde(default)]
    pub unconditional_modifies_params: HashSet<usize>,
    /// Parameters the coverage walk could only cover by FORWARDING them to a
    /// callee, keyed to the `(callee, callee parameter index)` pairs that
    /// have to be MUST-writes themselves for the coverage to hold.
    ///
    /// The obligation cannot be discharged where it is raised: a callee
    /// defined in another file has no summary yet while this one is being
    /// built, which is why the free version propagates in prescan rather
    /// than in `analyze_param_usage` too. `propagate_transitive_modifies`
    /// settles these once every file's summary exists.
    ///
    /// Kept separate from `unconditional_param_passthroughs` because that
    /// set answers a different question -- whether the forwarding call site
    /// is unconditionally reached -- and the answer here is routinely no.
    /// sqlite's `fts5CsrPoslist` forwards `pa` from inside an if/else whose
    /// other arm writes it directly, so no single call site is
    /// unconditional and yet no returning path leaves `pa` untouched
    /// .
    #[serde(default)]
    pub modifies_params_pending: HashMap<usize, Vec<(String, usize)>>,
    /// Parameters PROVEN to have a returning path that writes nothing through
    /// them — the positive-evidence half of what `modifies_params` minus
    /// `unconditional_modifies_params` only hints at.
    ///
    /// The difference matters because the MUST set is deliberately
    /// incomplete: it is built by demotion from a text scan and cannot see
    /// through an indirect call, so a genuine write-on-every-path function
    /// routinely fails to reach it. curl's `Curl_conn_get_current_host` fills
    /// both its outputs on every path, one of them via
    /// `cf_proxy->cft->query(...)` through a function pointer — absent from
    /// MUST, and yet crediting its callers is correct. Withholding the
    /// `&var`-initializes default on "not in MUST" alone therefore reports
    /// every such caller (a real-world bug).
    ///
    /// So this set answers the other question outright: is there a path that
    /// reaches a `return` (or the end of a void body) having neither written
    /// through the parameter nor handed it to anything that might?
    /// `Curl_sasl_decode_mech`'s trailing `return 0` is exactly that path —
    /// every write to `*len` sits inside the table-match `if`, and a caller
    /// reading the length on the no-match path reads it uninitialised.
    #[serde(default)]
    pub conditional_modifies_params: HashSet<usize>,
    /// For a subset of `conditional_modifies_params`'s indices, the PROVEN
    /// correlation between the write and this function's own return value --
    /// see `init_state::ReturnCorrelation`. Populated only when every one of
    /// this function's returning paths resolves to a literal-constant (or a
    /// local variable holding one) truthiness, and the write happened on
    /// every path of one truthiness and none of the other: lua's
    /// `lua_getstack` returns `1` on every path that wrote `*ar` and `0` on
    /// every path that did not.
    ///
    /// Absent for an index means unproven, not "no correlation" -- a caller
    /// checking the return value gets no extra credit, same as before this
    /// field existed.
    #[serde(default)]
    pub conditional_write_return_correlation: HashMap<usize, init_state::ReturnCorrelation>,
    /// Indices where two definitions linked under this name proved OPPOSITE
    /// `conditional_write_return_correlation` values during `merge_summary_variant`.
    /// Kept separate (unioned, so it is order-independent across however many
    /// variants disagree) rather than just deleting the index from that map
    /// on conflict: deleting alone lets a THIRD variant folded in afterward
    /// silently resurrect it with its own (equally untrustworthy) value,
    /// which is exactly the merge-order-dependent bug this file's own
    /// history warns about for `can_return_null` and the output-parameter
    /// sets.
    #[serde(default)]
    pub conditional_write_return_correlation_conflicted: HashSet<usize>,
    /// Parameter indices whose **pointee** this function frees — `free(*param)`,
    /// the `void **` "safe free" wrapper idiom:
    ///
    /// ```c
    /// void safe_free(void **ptr) { if (ptr && *ptr) { free(*ptr); *ptr = NULL; } }
    /// ```
    ///
    /// Distinct from `frees_params`, which says the pointer value handed in is
    /// released. Here it is the caller's own pointer *variable* that is
    /// released, and the call site names it as `&var`, so a rule matching
    /// arguments by identifier never sees the connection — which is what made
    /// every allocation in a `safe_free()`-using function look unmatched.
    /// A MAY-free fact, like `frees_params`.
    #[serde(default)]
    pub frees_param_pointees: HashSet<usize>,
    /// This function takes exactly ONE parameter and hands it to a call whose
    /// callee is not a plain name: a function pointer reached through a
    /// field, a deref or a parameter (`sqlite3GlobalConfig.m.xFree(p)`,
    /// lua's `(*g->frealloc)(ud, block, ...)`). Nothing is known about what
    /// runs, so this says only that the body's treatment of that parameter
    /// is UNREADABLE from there on.
    ///
    /// It is not a free fact and never credits one on its own. It exists so
    /// a consumer can tell "the body was read and releases nothing" from
    /// "the body was read and the release, if any, went somewhere
    /// unreadable" -- two states an empty `frees_params` conflates.
    /// `sqlite3_free(void *p)` frees exactly through `xFree`, so its summary
    /// is empty in every free set, which read as a REFUTATION of its
    /// `*_free` name and made every `sqlite3_free(a)` in the corpus count
    /// for nothing. The same "unseen, not nothing" reading
    /// `resolve_name_shaped_frees` already applies to an empty `may_free`.
    ///
    /// ARITY ONE IS THE WHOLE GUARD, and it is the one-nameable-argument
    /// rule of an earlier fix a level down. A name shape says a release happened
    /// and never says through WHICH parameter, and an escape into an
    /// unreadable call is no better: a comparator, a callback or a trace
    /// hook reads its argument and is spelled identically. With a second
    /// parameter the two questions come apart and the guess has no basis --
    /// measured, on the fix that lacked this guard: `Curl_conn_close(data,
    /// sockindex)` and `Curl_cwriter_free(data, writer)` reported curl's
    /// `data` as double-freed, and `Curl_hash_delete(h, key, key_len)`
    /// reported the lookup KEY freed. With one parameter there is nothing
    /// else the name could be about.
    ///
    /// A consumer that combines this with a deallocator NAME is still making
    /// a guess, not reading evidence, and must treat the credit as one --
    /// enough to withhold a leak report, never enough to accuse a later
    /// `free(p)` of being a double free.
    #[serde(default)]
    pub sole_param_escapes_unnamed_call: bool,
    /// Parameter indices whose VALUE this function stores somewhere that
    /// outlives the call — the ownership half `frees_params` does not cover.
    ///
    /// Passing a pointer to a callee was never an escape, so a function that
    /// hands its allocation to a container, a context or a registry looked
    /// like the block's only owner and every later `return` read as a leak:
    /// curl's `hash_elem_link(h, slot, he)`, `Curl_conn_meta_set(conn, key,
    /// ps, dtor)`, hostap's `eap_peer_method_register(eap)`.
    ///
    /// A MAY fact, like `frees_params`, and deliberately so. hostap's
    /// register idiom frees the argument on two error paths and links it into
    /// a list on the others, so MUST-free is empty AND MUST-store is empty
    /// while the UNION covers every path. Only MAY can express "this callee
    /// took ownership one way or the other", which is the whole question a
    /// leak check is asking, and it is the polarity the consumer wants: the
    /// fact SUPPRESSES a leak report, and a suppression needs may-escape.
    ///
    /// Credited on positive evidence read off the callee's own body, never
    /// on a name shape — the destination's root (`deref_write_root`) is
    /// another parameter (`*he_anchor = he`), a file-scope variable
    /// (`eap_methods = method`), or a local this function returns
    /// (`he->ptr = p` in a body ending `return he`). `propagate_transitive_
    /// stores` then carries it through forwarding wrappers, which is the only
    /// way the `Curl_conn_meta_set` -> `Curl_hash_add2` -> `hash_elem_create`
    /// chain is reachable at all: that function's own failure arm releases
    /// the block through a FUNCTION-POINTER PARAMETER (`meta_dtor(...)`),
    /// which no summary and no name can read.
    #[serde(default)]
    pub stores_params: HashSet<usize>,
    /// Whether this function can return NULL.
    pub can_return_null: bool,
    /// Whether this function returns dynamically allocated memory.
    pub returns_allocation: bool,
    /// Whether the declared return type is a pointer. Gates
    /// `propagate_returns_allocation`: only a pointer-returning wrapper can
    /// hand a callee's block back to its own caller.
    #[serde(default)]
    pub returns_pointer: bool,
    /// Callees whose results may reach a `return` of this function, by the
    /// routes `body_returned_callees` follows: the call itself, a name
    /// assigned from it through plain copies, either arm of a `?:`, an
    /// offset off the block. Wider than `returns_from_callees` (a direct
    /// `return f(...)` only), which the taint fixpoint keeps as is; this
    /// set closes `returns_allocation` and `returned_value_escapes` through
    /// `scard = os_zalloc(n); ... return scard;`, which names no allocator
    /// itself.
    #[serde(default)]
    pub returned_callees: HashSet<String>,
    /// MAY: the object this function returns was, before the return, put
    /// somewhere that outlives the call -- stored into a destination rooted
    /// in a parameter or a file-scope variable (`list->head = obj`), or
    /// handed to a callee whose `stores_params` covers that argument
    /// (`dl_list_add(&ctx->list, &obj->list)`; an interior pointer counts,
    /// since the block is reachable through it). A get-or-create-and-link
    /// constructor's result is therefore BORROWED by its caller: dropping it
    /// leaks nothing the container does not still hold. Read off the body
    /// and the callees' own summaries, never a name (same
    /// polarity as `stores_params`).
    #[serde(default)]
    pub returned_value_escapes: bool,
    /// `(callee, argument index)` pairs through which the returned object, or
    /// an interior pointer into it, was passed. Resolved against the callee's
    /// `stores_params` in `propagate_returned_value_escapes`, after every
    /// summary exists.
    #[serde(default)]
    pub returned_value_passthroughs: HashSet<(String, usize)>,
    /// Parameter indices that this function checks for NULL.
    pub checks_null_params: HashSet<usize>,
    /// Parameter indices that this function writes through (modifies via pointer).
    pub modifies_params: HashSet<usize>,
    /// Parameter indices that this call unconditionally sets to NULL.
    ///
    /// Real functions never populate this (no AST pass derives it from a
    /// function body) — it exists so a "safe free" function-like macro
    /// invocation (`mosquitto_FREE(p)`, `Curl_safefree(p)`, `SAFE_FREE(p)`,
    /// detected structurally by `macro_expand::macro_nulls_param_indices`,
    /// not by name) can be synthesized into a one-off `FunctionSummary` entry
    /// keyed by the macro's name, exactly as `modifies_params` already is for
    /// write-through macros (see EXP34-C's `macro_write_params`/MEM30-C's
    /// `macro_null_params`). `null_state.rs`'s
    /// `apply_cross_file_nulls_params_null` reads it the same way
    /// `apply_cross_file_output_params_null` reads `modifies_params`, so a
    /// bare `mosquitto_FREE(auth_method);` statement (a plain call_expression
    /// with no `= NULL` assignment visible to the parser) marks `auth_method`
    /// `DefinitelyNull` for the rest of the CFG, the same as if the caller had
    /// written `free(auth_method); auth_method = NULL;` by hand.
    #[serde(default)]
    pub nulls_params: HashSet<usize>,
    /// The parameter this callee returns only when true: a call with a false
    /// argument there never returns. Real functions never set this; it is
    /// synthesized per file for the assert-style macros no configuration
    /// compiles out (`check_macros::abort_check_macros`, valkey's
    /// `serverAssert`), so `null_state.rs` reads `M(p != NULL);` the way it
    /// reads `if (!p) abort();`.
    #[serde(default)]
    pub returns_only_if_param_true: Option<usize>,
    /// Parameter indices that this function dereferences in any way (read or write).
    /// Superset of modifies_params — includes `*param`, `param[i]`, `param->field`.
    pub dereferences_params: HashSet<usize>,
    /// Parameter indices this function uses as a pointer in any way: every
    /// `dereferences_params` index, plus one reached only by forming a member
    /// address (`&param->field`), which `dereferences_params` deliberately
    /// leaves out because it does not READ the parameter.
    ///
    /// API00-C asks the wider question. `&param->field` on a null `param` is
    /// already undefined, and whatever receives that address reads a small
    /// offset from null, so a forwarder into such a callee hands it an
    /// unvalidated pointer all the same. EXP33-C and MEM01-C keep
    /// the read-only test; this set is for callers asking "is it used".
    #[serde(default)]
    pub uses_params: HashSet<usize>,
    /// Parameter indices this function null-checks **before** its first
    /// dereference of them. Subset of `checks_null_params`.
    ///
    /// The ordering is the whole point. A caller asking "is it safe to hand
    /// this callee an unvalidated pointer?" is answered by
    /// `checks_null_params` only when the check happens first: a callee that
    /// dereferences `conn` at `if (conn->client)` and null-tests it on some
    /// later path has still crashed. That distinction is what separates a
    /// real callee summary from "the pointer was forwarded to a helper,
    /// assume it is checked" — a shortcut that turns confirmed true positives
    /// into misses, since at the flagged function a safe forwarding wrapper
    /// and an unsafe one are structurally identical and only the callee's
    /// body tells them apart.
    #[serde(default)]
    pub checks_null_params_before_deref: HashSet<usize>,
    /// Whether this function never returns (calls abort/exit/longjmp).
    pub never_returns: bool,
    /// Aggregated null states of arguments at all call sites (populated by prescan second pass).
    /// Maps parameter index → joined NullState from all callers.
    pub callsite_param_null_states: HashMap<usize, NullState>,
    /// Parameter indices every visible call site passes a provably non-null
    /// argument at. Strictly stronger than a `NotNull` in
    /// `callsite_param_null_states`, which is a majority VOTE:
    /// `Unknown` callers there contribute nothing and a `PossiblyNull` caller
    /// can be outvoted, so that map answers "what do callers mostly do?" and
    /// this set answers "did every one of them prove it?". Only the latter can
    /// license discarding a null disjunct.
    ///
    /// Sound as a proof of the parameter's entry state ONLY together with
    /// [`Self::has_internal_linkage`]: for a non-static function, callers can
    /// live in a translation unit the prescan never saw, so "every call site
    /// we found" is not "every call site".
    #[serde(default)]
    pub callsite_param_proven_nonnull: HashSet<usize>,
    /// `static` at file scope — every caller is in this translation unit, so
    /// the prescanned call sites are provably all of them.
    #[serde(default)]
    pub has_internal_linkage: bool,
    /// This function's name is mentioned somewhere as a VALUE rather than
    /// called directly: `&handler`, `{ .cb = handler }`, `register(handler)`.
    ///
    /// What it withdraws is the claim
    /// [`Self::has_internal_linkage`] makes on its own —
    /// "the prescanned call sites are provably all of them". They are all the
    /// SYNTACTIC ones; a call through the stored pointer is a call site with
    /// no `identifier(...)` anywhere to collect, so a static callee in a
    /// dispatch table can be handed a null by code that never names it. So
    /// `callsite_param_proven_nonnull` is withheld for such a function while
    /// the majority vote in `callsite_param_null_states`, which never
    /// licenses discarding a null, is left alone.
    ///
    /// Deliberately over-approximate: it is a name match, so a local variable
    /// sharing a function's spelling sets it. `docs/adr/0006` forbids
    /// resolving what an occurrence REFERS to by spelling, and this does not
    /// do that -- the flag only ever takes a proof away, so a spurious match
    /// costs a suppression and can never manufacture one.
    #[serde(default)]
    pub address_taken: bool,
    /// The number of fixed (named) parameters before a trailing `...`, for a
    /// variadic function declaration. `None` for a non-variadic function.
    ///
    /// A vararg position has no parameter index in this summary to seed the
    /// callee's own null-state analysis with (`vprintf(fmt, ap)` never
    /// resolves which named caller variable reached a given `%s` from
    /// inside the callee's body), so a caller passing a possibly-null
    /// pointer into one is only ever observable at the call site. EXP34-C's
    /// call-site check is scoped to exactly these positions — an earlier fix.
    #[serde(default)]
    pub variadic_from: Option<usize>,
    /// Argument-position pairs `(lower, higher)` at which SOME call site
    /// anywhere in the pre-scanned project hands this function two named,
    /// DIFFERENT storage objects.
    ///
    /// The caller-side fact ARR36-C's parameter model needs: two pointer
    /// parameters are taken to share an object unless a caller proves
    /// otherwise, and a callee whose callers all live in other translation
    /// units has no such proof in its own file. Distinctness is
    /// per CALL SITE rather than per position -- one caller passing `a` at
    /// index 0 and a different caller passing `b` at index 1 proves nothing,
    /// because no single path ever holds both. One proving call site IS
    /// enough: the comparison inside the callee is undefined whenever that
    /// caller's path runs.
    #[serde(default)]
    pub distinct_object_param_pairs: HashSet<(usize, usize)>,
    /// Aggregated null states of struct fields within arguments at all call sites.
    /// Maps parameter index → field name → joined NullState from all callers.
    /// Used for variant 67 struct field null propagation across functions.
    #[serde(default)]
    pub callsite_param_field_null_states: HashMap<usize, HashMap<String, NullState>>,
    /// Aggregated null states of pointed-to values in address-of arguments.
    /// Maps parameter index → null state of the variable whose address was taken.
    /// Used for variant 63 pointer-to-pointer null propagation across functions.
    #[serde(default)]
    pub callsite_param_pointee_null_states: HashMap<usize, NullState>,
    /// Computed return value range for integer-returning functions.
    /// `Some(range)` when all return paths provably return values in [min, max].
    /// `None` for void, pointer-returning, or unevaluable return expressions.
    pub return_range: Option<ValueRange>,
    /// True when the function returns a value and EVERY `return` expression in
    /// its body is fixed at compile time — a literal, `sizeof`, a macro
    /// constant or enumerator, or arithmetic over those — in the weak sense of
    /// [`const_eval::is_compile_time_constant_expr`], which does not require
    /// the value to fold.
    ///
    /// The fact `return_range` cannot carry: seL4's `pageBitsForSize()` is a
    /// switch returning one of three enumerators whose definitions live in a
    /// generated header outside the scan, so every return expression is
    /// unfoldable and `return_range` is `None` even though the call is no more
    /// of a runtime hazard than a literal. Lets INT34-C hoist its
    /// constant-shift-amount reasoning across a call.
    #[serde(default)]
    pub returns_only_compile_time_constants: bool,
    /// Parameter pass-through: which of this function's params are forwarded to
    /// callees. Maps caller_param_idx → Vec<(callee_name, callee_param_idx)>.
    /// Used for transitive free propagation (MEM31-C).
    #[serde(default)]
    pub param_passthroughs: HashMap<usize, Vec<(String, usize)>>,
    /// Parameter indices this function's body forwards, as a bare
    /// identifier, into a call this build can never resolve to a specific
    /// function -- a call through a `field_expression` (`obj->cb(...)`,
    /// `obj.cb(...)`), the same C-semantics test
    /// `prescan::collect_ambiguous_call_targets` uses for the call graph:
    /// the field name has no relationship to any global
    /// function of the same name, so nothing this build has can say
    /// whether the runtime-bound callee writes through the parameter.
    ///
    /// A MAY fact, deliberately: reaching the indirect call on ANY path is
    /// enough, because this isn't a coverage proof like
    /// `unconditional_modifies_params` -- it's the honest "cannot know" a
    /// read-only classification needs before asserting a violation
    /// (ADR-0001). `propagate_forwards_to_indirect_call` carries it through
    /// `param_passthroughs` chains, since the indirection is routinely one
    /// or more hops below the parameter the real caller passed: hostap's
    /// `accounting_sta_update_stats` forwards its own `data` param to the
    /// named (and otherwise ordinary) `hostapd_drv_read_sta_data`, which is
    /// where the actual `hapd->driver->read_sta_data(...)` dispatch lives
    /// (see EXP33-C piece (b) of
    /// docs/design/exp33-c-cross-file-uninit-architecture.md).
    #[serde(default)]
    pub forwards_to_indirect_call: HashSet<usize>,
    /// Subset of `param_passthroughs` whose forwarding CALL SITE is itself
    /// unconditional (not nested inside an if/switch/loop/ternary). Used to
    /// propagate `unconditional_frees_params` transitively — a passthrough
    /// at a conditional call site can't make the caller's free
    /// unconditional even if the callee's own free is.
    #[serde(default)]
    pub unconditional_param_passthroughs: HashMap<usize, Vec<(String, usize)>>,
    /// Struct field names freed directly off a parameter within this function's
    /// body, e.g. `free(param->name)` or `free((*param)->name)`. Maps
    /// param_idx → set of field names. Lets MEM31-C credit a custom
    /// deallocator (e.g. `destroy_person(&p)`) with freeing `p->name` even
    /// though the free happens inside the callee, not the caller (an earlier fix:
    /// MEM31-C ownership model).
    #[serde(default)]
    pub frees_param_fields: HashMap<usize, HashSet<String>>,
    /// True if the function body contains a call to a known taint-source
    /// function (recv, fgets, scanf, getenv, ...). Used by ENV03-C to
    /// decide whether a helper function's callers are passing in
    /// externally-controlled data.
    #[serde(default)]
    pub has_env03_taint_source: bool,
    /// True if this function's return value may carry externally-controlled
    /// data. Seeded from `has_env03_taint_source` for non-void returns, then
    /// propagated to fixpoint through `returns_from_callees` so a wrapper
    /// like `char *wrap() { return readIt(); }` is also marked tainted.
    #[serde(default)]
    pub returns_tainted: bool,
    /// Names of callees whose return values flow directly to a `return`
    /// statement in this function's body. Used for transitive return-value
    /// taint propagation in prescan.
    #[serde(default)]
    pub returns_from_callees: HashSet<String>,
    /// True if this function calls strcpy/strcat/wcscpy/wcscat with a second
    /// argument that is a known non-absolute-path macro (e.g.,
    /// `BAD_OS_COMMAND = "ls -la"`). Used by ENV03-C's caller-aware
    /// suppression: a sink's callers that set relative-path commands are NOT
    /// clean, regardless of `has_env03_taint_source`.
    #[serde(default)]
    pub has_relative_command_write: bool,
    /// Integer constant values for parameters where ALL call sites within the
    /// project pass the same constant literal. Maps parameter index → value.
    /// Absent entry means callers disagree or pass non-constant arguments.
    /// Used by VRA to narrow parameter entry ranges so integer overflow rules
    /// suppress goodG2B-style FPs where data is provably a small constant.
    #[serde(default)]
    pub callsite_param_const_int: HashMap<usize, i64>,
    /// Minimum element-count buffer size passed by callers at each parameter
    /// position, recorded only when EVERY call site within the project passes a
    /// pointer to a buffer of statically-known size. Absent when any caller
    /// passes an unresolvable buffer, or the function is header-declared (so
    /// external callers are unknown). Used by STR31-C to prove a parameter
    /// destination is large enough for the copied content and suppress the
    /// cross-function goodG2BSink false positives (Juliet variants 41+).
    #[serde(default)]
    pub callsite_param_buffer_size: HashMap<usize, usize>,
    /// Like `callsite_param_buffer_size`, but for a struct-by-value
    /// parameter whose FIELD (not the parameter itself) holds the buffer
    /// pointer: maps parameter index → field name → minimum element-count
    /// buffer size that field resolves to across every call site. A field
    /// is present only when every call site passing a value at that
    /// parameter position is a plain identifier AND that identifier's
    /// caller-local tracking resolved this exact field to a known static
    /// buffer size — a call site that passes a non-identifier expression,
    /// or an identifier whose tracking never pins this field down,
    /// disqualifies the field entirely rather than being skipped, mirroring
    /// `callsite_param_buffer_size`'s "trust only when every caller
    /// resolves" discipline at field granularity. Used by ARR38-C to
    /// resolve Juliet flow variant 67 (`data flow: data passed in a struct
    /// from one function to another, often in different source files`),
    /// where the sink function's own body only sees `data = myStruct.field;`
    /// with no idea what the caller set `field` to.
    #[serde(default)]
    pub callsite_param_field_buffer_size: HashMap<usize, HashMap<String, usize>>,
    /// Maximum element-count buffer size or memset-fill content length this
    /// function itself writes into a parameter (via a direct/aliased
    /// malloc-family allocation assigned to it, or a `memset` fill followed
    /// by an explicit null terminator on it) before returning. The opposite
    /// direction of `callsite_param_buffer_size`: that records what CALLERS
    /// pass in, this records what THIS function PRODUCES for its own
    /// parameter. Lets STR31-C resolve a same-file-or-cross-file "source
    /// relay" pattern — `data = someSource(data)`, where `someSource`
    /// conditionally allocates or content-fills its own parameter and
    /// returns it (Juliet flow variants 21/22) — without needing the
    /// callee's AST in the current file, the way the same-file case does.
    #[serde(default)]
    pub produces_param_buffer_size: HashMap<usize, usize>,
    /// Parameter indices that this function closes (e.g., `fclose(param)`,
    /// `close(param)`, `CloseHandle(param)`). Mirrors `frees_params` but for
    /// FIO42-C's file/descriptor/handle resources instead of heap memory.
    /// Propagated transitively through `param_passthroughs` by
    /// `propagate_transitive_closes`, so a resource opened in one function and
    /// closed by a sink helper it's passed to (directly or through a chain of
    /// forwarding wrappers) is recognized as closed.
    #[serde(default)]
    pub closes_params: HashSet<usize>,
    /// Parameter indices whose pointee this function overwrites: the body
    /// hands the parameter, as the destination, to one of
    /// `call_roles::MEMORY_CLEARING_FUNCS`, to a file-scope function pointer
    /// initialised from one (`static void *(*const volatile memset_func)(...)
    /// = memset;`, the volatile-pointer idiom that keeps the compiler from
    /// eliding the store), or to another function that does either
    /// (`propagate_transitive_clears`). A project's zeroize wrapper --
    /// mbedtls's `mbedtls_platform_zeroize`, hostap's `forced_memzero` -- is
    /// a clearer by this fact, not by name, and MEM03-C credits its callers
    /// with clearing the buffer.
    ///
    /// Credited for a definition inside a preprocessor conditional like any
    /// other: mbedtls's real zeroize is itself under
    /// `#if !defined(MBEDTLS_PLATFORM_ZEROIZE_ALT)`.
    #[serde(default)]
    pub clears_params: HashSet<usize>,
    /// Parameter indices where at least one call site within the project
    /// passes an argument recognized as tainted (a known user-input source,
    /// `argv`, or data traced back to one via a direct assignment/string-copy
    /// chain within the caller). Paired with `callsite_param_taint_observed`
    /// so an absent index can be told apart from "definitely never tainted":
    /// only trust an index as taint-free when `callsite_param_taint_observed`
    /// also contains it. Used by FIO30-C to extend its intra-file wrapper
    /// taint fixpoint across files — Juliet's CWE-134 b/c/d/e flow variants
    /// put the sink helper (e.g. `badSink`/`goodG2BSink`) in a different file
    /// than its single caller, so a per-translation-unit analysis can never
    /// observe whether that caller passed a literal or tainted value.
    #[serde(default)]
    pub callsite_param_tainted: HashSet<usize>,
    /// Parameter indices for which at least one call site within the project
    /// was observed at all (regardless of taintedness). See
    /// `callsite_param_tainted` for why this companion set exists.
    #[serde(default)]
    pub callsite_param_taint_observed: HashSet<usize>,
    /// Parameter indices whose argument EVERY call site seen anywhere in the
    /// scanned project already bounds-checks with a dominating comparison
    /// before passing (`if (i < n) callee(i)`), with at least one such call
    /// site observed. The cross-file half of ARR30-C's validate-then-act
    /// suppression: a callee written to trust an index its callers range-check
    /// reads, on its own body, exactly like one that forgot to check.
    ///
    /// Only bare-variable arguments can be validated — see
    /// `guard_dominance::call_arg_guards`, which produces the per-site flags
    /// this aggregates — so a single call site passing an expression, or
    /// passing an unguarded variable, disqualifies the position entirely.
    #[serde(default)]
    pub callsite_param_validated: HashSet<usize>,
    /// The definition's parameter list is empty or exactly `(void)`, so no
    /// value a caller passes can reach its body through a parameter. That is
    /// where a walk up the reverse call graph for "what reaches this value"
    /// can stop: see [`every_caller_is_clean`]. False whenever the list is
    /// anything else, including a K&R identifier list, and whenever the
    /// declarator is too unusual to be sure.
    #[serde(default)]
    pub declares_no_params: bool,
}

impl FunctionSummary {
    /// Whether the call sites the scan collected for this function are
    /// provably ALL of them, so that what every one of them passes is a fact
    /// about the parameter rather than about today's callers (ADR-0011,
    /// "checks made by every caller count").
    ///
    /// Two things have to hold. The function has internal linkage, so no
    /// translation unit the scan never saw can call it -- a non-static
    /// function is open whether or not a header declares it, since a library
    /// exports it and `-rdynamic` exports it from an executable. And its
    /// address stays inside the scanned source (`address_taken` is false), so
    /// no call is made through a stored pointer by code that never names it.
    ///
    /// This is the gate every caller-set proof goes through: a constant every
    /// caller passes, a minimum buffer size, "no caller passes taint", "every
    /// caller range-checks the index", reachability from a thread root. It
    /// says nothing about how many call sites there are; a proof also needs
    /// at least one, which each aggregation checks for itself.
    pub fn caller_set_is_closed(&self) -> bool {
        self.has_internal_linkage && !self.address_taken
    }
}

/// Names of functions that read externally-controlled data into their
/// arguments or return values. A function whose body calls any of these
/// is treated as a potential taint origin for ENV03-C caller analysis.
/// Keep in sync with `env03_c::TAINT_SOURCES`.
pub const ENV03_TAINT_SOURCE_FUNCTIONS: &[&str] = &[
    "recv",
    "recvfrom",
    "recvmsg",
    "WSARecv",
    "WSARecvFrom",
    "accept",
    "read",
    "fread",
    "fgets",
    "gets",
    "getchar",
    "getc",
    "fgetc",
    "scanf",
    "fscanf",
    "sscanf",
    "vscanf",
    "vfscanf",
    // Wide-character input — mirror the narrow-char taint sources.
    // Juliet's wchar_t_console / wchar_t_file variants read via fgetws,
    // and without these the caller's summary is (incorrectly) clean,
    // causing caller-aware suppression to drop the bad-path TP.
    "fgetws",
    "getwchar",
    "getwc",
    "fgetwc",
    "wscanf",
    "fwscanf",
    "swscanf",
    "vwscanf",
    "vfwscanf",
    "_getws",
    "_getws_s",
    "getenv",
    "secure_getenv",
    "_wgetenv",
    "_wgetenv_s",
    "ReadFile",
    "ReadConsole",
    "ReadConsoleA",
    "ReadConsoleW",
    "RegQueryValueExA",
    "RegQueryValueExW",
];

fn body_contains_taint_source(body_text: &str) -> bool {
    ENV03_TAINT_SOURCE_FUNCTIONS
        .iter()
        .any(|name| body_text.contains(&format!("{}(", name)))
}

fn body_contains_alias(body_text: &str, aliases: &[String]) -> bool {
    aliases
        .iter()
        .any(|alias| body_text.contains(&format!("{}(", alias)))
}

/// True if the function body calls strcpy/strcat/wcscpy/wcscat with a second
/// argument that is a macro identifier whose string value is a non-absolute path.
/// Detects CWE-426 patterns like `strcpy(data, BAD_OS_COMMAND)` where
/// `BAD_OS_COMMAND = "ls -la"`.
fn body_has_relative_command_write(
    body: &Node,
    source: &str,
    string_macros: &HashMap<String, String>,
) -> bool {
    let mut found = false;
    walk_for_relative_command_write(body, source, string_macros, &mut found);
    found
}

fn walk_for_relative_command_write(
    node: &Node,
    source: &str,
    string_macros: &HashMap<String, String>,
    found: &mut bool,
) {
    if *found {
        return;
    }
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            let raw = func.utf8_text(source.as_bytes()).unwrap_or("");
            let ident = raw
                .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or(raw);
            if matches!(
                ident,
                "strcpy"
                    | "strcat"
                    | "stncpy"
                    | "strncat"
                    | "wcscpy"
                    | "wcscat"
                    | "wcsncpy"
                    | "wcsncat"
            ) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    let named: Vec<_> = (0..args.child_count())
                        .filter_map(|i| args.child(i))
                        .filter(|c| c.is_named())
                        .collect();
                    // Second named arg is the source string for str/wcs copy/cat
                    if let Some(second) = named.get(1) {
                        let s = *second;
                        if s.kind() == "identifier" {
                            let nm = s.utf8_text(source.as_bytes()).unwrap_or("");
                            if const_eval::is_relative_command_macro(string_macros, nm) {
                                *found = true;
                                return;
                            }
                        }
                    }
                }
            }
        }
        // Don't recurse into call_expression arguments here — the call
        // itself was checked; inner calls are handled by the outer loop.
        return;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            // Don't cross into a nested (swallowed-sibling) function boundary.
            if is_real_nested_function_definition(&child, source) {
                continue;
            }
            walk_for_relative_command_write(&child, source, string_macros, found);
            if *found {
                return;
            }
        }
    }
}

/// Compute function summaries for all function definitions in the AST.
///
/// When `compute_return_ranges` is true, also computes return value ranges
/// for integer-returning functions (needed for VRA inter-procedural analysis).
/// Pass false during prescan when no VRA-consuming rules are enabled.
pub fn compute_summaries(
    root: &Node,
    source: &str,
    macros: &MacroConstantMap,
    compute_return_ranges: bool,
    taint_source_aliases: &[String],
    string_macros: &HashMap<String, String>,
    function_macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
) -> HashMap<String, FunctionSummary> {
    let mut summaries = HashMap::new();

    let clearing_names = collect_clearing_names(root, source);

    collect_function_summaries(
        root,
        source,
        macros,
        compute_return_ranges,
        taint_source_aliases,
        string_macros,
        function_macros,
        &clearing_names,
        &mut summaries,
    );

    summaries
}

/// The callee names that overwrite their first argument's pointee in this
/// file: `call_roles::MEMORY_CLEARING_FUNCS` plus every file-scope
/// declarator initialised from one of them -- the
/// `static void *(*const volatile memset_func)(void *, int, size_t) = memset;`
/// idiom (mbedtls `platform_util.c`, hostap `common.c`) that a zeroize
/// wrapper calls INSTEAD of `memset` precisely so the call cannot be
/// optimised away. Feeds `credit_clears_params`.
fn collect_clearing_names(root: &Node, source: &str) -> HashSet<String> {
    use crate::utility::cert_c::{ast_utils, call_roles};
    use lang_parsing_substrate::query;

    let mut names: HashSet<String> = call_roles::MEMORY_CLEARING_FUNCS
        .iter()
        .map(|n| n.to_string())
        .collect();
    for decl in query::find_descendants_of_kind(*root, "declaration") {
        if query::find_ancestor(decl, |a| a.kind() == "function_definition").is_some() {
            continue;
        }
        let mut cursor = decl.walk();
        for init in decl.children_by_field_name("declarator", &mut cursor) {
            if init.kind() != "init_declarator" {
                continue;
            }
            let (Some(declarator), Some(value)) = (
                init.child_by_field_name("declarator"),
                init.child_by_field_name("value"),
            ) else {
                continue;
            };
            let target = init_state::strip_arg_casts(&value);
            if target.kind() != "identifier"
                || !call_roles::is_memory_clearing_call(
                    target.utf8_text(source.as_bytes()).unwrap_or(""),
                )
            {
                continue;
            }
            let name = ast_utils::get_identifier_from_declarator(&declarator, source);
            if !name.is_empty() {
                names.insert(name);
            }
        }
    }
    names
}

#[allow(clippy::too_many_arguments)]
fn collect_function_summaries(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    compute_return_ranges: bool,
    taint_source_aliases: &[String],
    string_macros: &HashMap<String, String>,
    function_macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
    clearing_names: &HashSet<String>,
    summaries: &mut HashMap<String, FunctionSummary>,
) {
    // Iterative pre-order rather than recursion, and the order is the same one
    // a recursive descent produced (children pushed reversed, popped LIFO), so
    // which definition wins a duplicate name is unchanged.
    //
    // The walk below descends into EVERY child, so its depth is the AST's own
    // nesting depth -- unbounded, and reached in practice by a file whose
    // #ifdef braces make tree-sitter nest every remaining function inside the
    // last good one. As recursion that cost one stack frame per level, each
    // holding an `analyze_function` result, so the frame grew with
    // `FunctionSummary` itself: raylib's parse aborted the entire scan the
    // next time the struct gained a field, and would have again on the one
    // after that. Depth now costs heap.
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if current.kind() == "function_definition" && !is_macro_function_definition(&current) {
            if let Some(name) = extract_function_name(&current, source) {
                let summary = analyze_function(
                    &current,
                    source,
                    macros,
                    compute_return_ranges,
                    taint_source_aliases,
                    string_macros,
                    function_macros,
                    clearing_names,
                );
                // Two definitions of one name in a single translation unit --
                // the `#ifdef FEATURE` real implementation beside the `#else`
                // stub, which aurora-lint sees both of because it does not
                // preprocess. Folded exactly as two definitions in different
                // files are: `merge_summary_variant` is the one place that
                // decides what callers of a multiply-defined name are told
                // .
                //
                // The overwrite this replaces was LAST-one-wins, which is
                // worse than arbitrary here: the `#else` stub is textually
                // last, so the do-nothing variant systematically won and its
                // empty write sets governed every caller.
                match summaries.get_mut(&name) {
                    Some(existing) => merge_summary_variant(existing, summary),
                    None => {
                        summaries.insert(name, summary);
                    }
                }
            }
        }

        // Descend into every child unconditionally, not just preproc wrappers.
        // A brace that opens and closes in different branches of the same
        // repeated #ifdef guard makes tree-sitter-c's preprocessor-less parse
        // swallow every subsequent sibling function_definition as a nested
        // descendant of the corrupted one (see `is_real_nested_function_definition`
        // and lang_parsing_substrate::calls, which hit the identical failure
        // mode for call-graph edges). Stopping at preproc_* children only would
        // leave every swallowed sibling permanently invisible to this map — a
        // silent false-negative for every interprocedural rule keyed on
        // FunctionSummary (MSC04-C, EXP34-C, MEM30/31-C, null-state, taint).
        // Walking everywhere instead still finds and summarizes it under its
        // own name, even though it's nested in the AST.
        for i in (0..current.child_count()).rev() {
            if let Some(child) = current.child(i) {
                stack.push(child);
            }
        }
    }
}

/// True when a `function_definition` node is actually a macro invocation
/// mis-parsed as one (declarator is a parenthesized macro call like
/// `DEFINE_HANDLER(foo) { ... }`), not a real function.
fn is_macro_function_definition(node: &Node) -> bool {
    node.kind() == "function_definition"
        && node
            .child_by_field_name("declarator")
            .map(|d| d.kind() == "parenthesized_declarator")
            .unwrap_or(false)
}

/// True when `node` is a `function_definition` that represents a genuine
/// nested function boundary and not tree-sitter error-recovery debris (a
/// keyword like `if`/`while` mis-parsed as a nameless function whose "name"
/// resolves to the keyword itself) or a macro-invocation function_definition.
/// C has no real nested functions, so any node satisfying this while walking
/// another function's body is swallowed sibling content from a corrupted
/// parse and must not be treated as part of the enclosing function's own
/// summary — mirrors `lang_parsing_substrate::calls`'s identical guard for
/// call-graph edges.
fn is_real_nested_function_definition(node: &Node, source: &str) -> bool {
    if node.kind() != "function_definition" || is_macro_function_definition(node) {
        return false;
    }
    match extract_function_name(node, source) {
        Some(name) => !is_c_keyword(&name),
        None => true,
    }
}

fn is_c_keyword(name: &str) -> bool {
    matches!(
        name,
        "if" | "else"
            | "for"
            | "while"
            | "do"
            | "switch"
            | "case"
            | "default"
            | "return"
            | "break"
            | "continue"
            | "goto"
            | "sizeof"
            | "typedef"
            | "struct"
            | "union"
            | "enum"
    )
}

/// Finds the start byte of the first real nested `function_definition`
/// inside `node`'s subtree (`node` itself excluded), if any. Only meaningful
/// to call when `node.has_error()` — see `is_real_nested_function_definition`.
fn find_nested_function_boundary(node: &Node, source: &str) -> Option<usize> {
    for i in 0..node.child_count() {
        let child = node.child(i)?;
        if is_real_nested_function_definition(&child, source) {
            return Some(child.start_byte());
        }
        if let Some(boundary) = find_nested_function_boundary(&child, source) {
            return Some(boundary);
        }
    }
    None
}

/// Analyze a single function definition to produce its summary.
///
/// `taint_source_aliases` names any macro identifier whose target resolves to
/// a taint source (e.g. `#define GETENV getenv`) — treated as additional
/// text-scan keywords when computing `has_env03_taint_source`.
#[allow(clippy::too_many_arguments)]
fn analyze_function(
    func_node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    compute_return_ranges: bool,
    taint_source_aliases: &[String],
    string_macros: &HashMap<String, String>,
    function_macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
    clearing_names: &HashSet<String>,
) -> FunctionSummary {
    // Internal linkage: `static` storage class at file scope. A direct-child
    // scan, not a text one, so a `static` in the body or in a parameter type
    // cannot be mistaken for the function's own -- a `function_definition`
    // carries the specifier in the same child position a `declaration` does,
    // which is why the declaration-shaped helper is the right one here.
    let has_internal_linkage = crate::utility::cert_c::ast_utils::declaration_has_storage_class(
        func_node, "static", source,
    );

    let mut summary = FunctionSummary {
        has_internal_linkage,
        declares_no_params: declares_no_params(func_node, source),
        ..Default::default()
    };

    // Collect parameter names
    let params = collect_param_names(func_node, source);
    summary.variadic_from = detect_variadic_arity(func_node);

    // Check the return type
    let is_pointer_return;
    let is_void_return;
    if let Some(return_type) = func_node.child_by_field_name("type") {
        let type_text = return_type.utf8_text(source.as_bytes()).unwrap_or("");
        // Functions returning pointer types might return NULL. Walk the
        // declarator chain rather than substring-searching its text: a
        // plain `T foo(const u8 *arg)` declarator's *text* also contains
        // '*' (from the pointer parameter), which previously made every
        // function taking a pointer argument look like it returns a
        // pointer regardless of its actual return type.
        is_pointer_return = func_node
            .child_by_field_name("declarator")
            .is_some_and(|d| declarator_denotes_pointer_return(&d));
        is_void_return = type_text == "void";
        if is_pointer_return {
            // Could return NULL unless proven otherwise
            summary.can_return_null = true;
        }
        // void functions can't return NULL
        if is_void_return {
            summary.can_return_null = false;
        }
    } else {
        is_pointer_return = false;
        is_void_return = false;
    }

    // Analyze function body
    if let Some(body) = func_node.child_by_field_name("body") {
        // When the body's parse contains an error, it may be a case of the
        // brace-in-different-#ifdef-branches corruption: this function's
        // span swallowed a subsequent sibling as a nested function_definition
        // descendant. Bound the plain text scans below to the source before
        // that boundary so this function's summary isn't polluted with the
        // swallowed sibling's content (which gets its own, correctly-scoped
        // summary via `collect_function_summaries`'s unconditional recursion).
        // The AST-walking helpers below (check_never_returns is text-only;
        // the rest take `body` directly) each stop at the same boundary via
        // `is_real_nested_function_definition`, independent of this text
        // bound, so this stays correct even if boundary detection here ever
        // disagrees with theirs.
        let text_end = if body.has_error() {
            find_nested_function_boundary(&body, source).unwrap_or_else(|| body.end_byte())
        } else {
            body.end_byte()
        };
        let body_text = &source[body.start_byte()..text_end];

        // Check for never-returns patterns
        summary.never_returns = check_never_returns(body_text);

        // Check for returns-allocation pattern. Gated on the function's own
        // declared return type actually being a pointer: a non-pointer
        // (enum/int/u16/bool/...) function that merely calls malloc/calloc/
        // etc. somewhere in its body -- e.g. to fill an out-param or a
        // struct field -- does not hand a fresh allocation back to its
        // caller via the return value, so callers assigning its result to a
        // local must not have that local treated as owning fresh memory
        // (an earlier fix: MEM31-C flagging non-pointer status locals like `enum
        // wpa_validate_result`/`u16`/`int` as leaked/double-freed because
        // the assigning callee's body happened to contain a malloc call).
        // Comments are stripped first: a borrowed-accessor
        // function whose body has no allocator call at all but a doc
        // comment merely *mentioning* one -- e.g. sqlite3_column_blob()'s
        // "might need to call malloc() to expand..." -- must not count.
        //
        // The flag is now derived from what the `return` expressions flow
        // from, not from whether an allocator is spelled anywhere in the
        // body. hostap's wpa_sm_write_assoc_resp_ies
        // os_realloc()s a scratch buffer it frees on every path and returns
        // `pos`, a cursor into the caller's buffer; the substring scan
        // called it an allocator, and every caller's `p = ...(...)` cursor
        // was then reported as leaked by MEM31-C. The text scan survives
        // only as the fallback for a body whose parse recovered no `return`
        // at all.
        summary.returns_pointer = is_pointer_return;
        if is_pointer_return {
            match body_returned_callees(&body, source, text_end) {
                Some(callees) => {
                    summary.returns_allocation = callees.iter().any(|c| is_allocator_name(c));
                    summary.returned_callees = callees;
                }
                None => {
                    let body_text_no_comments = strip_comments_multiline(body_text);
                    summary.returns_allocation = body_text_no_comments.contains("malloc(")
                        || body_text_no_comments.contains("calloc(")
                        || body_text_no_comments.contains("realloc(")
                        || body_text_no_comments.contains("aligned_alloc(");
                }
            }
        }

        // Quick text scan for taint-source calls — used by ENV03-C to
        // classify callers as tainted/clean. Also matches any macro
        // identifier that aliases a known taint source (e.g.
        // `#define GETENV getenv`) so Juliet macro-wrapped sources still
        // poison the caller's summary.
        //
        // Comments and string literals stripped first (
        // aurora_lint, found by an earlier fix's rule architecture sweep): this
        // consumer is MUST-style, not suppression-only (ENV03-C gates "this
        // caller is clean" on `!has_env03_taint_source`), so a comment
        // merely mentioning a source (`// TODO: call getenv(x) here`) or a
        // string literal containing one (`"usage: getenv(VAR)"`) was a real
        // false-positive path, the same ADR-0005/ADR-0006 misfire shape as
        // `cast_then_deref` and `has_genuine_arrow_read`.
        let body_text_for_taint_scan = strip_string_literals(&strip_comments_multiline(body_text));
        summary.has_env03_taint_source = body_contains_taint_source(&body_text_for_taint_scan)
            || body_contains_alias(&body_text_for_taint_scan, taint_source_aliases);

        // Detect CWE-426-style relative-path command writes: strcpy/strcat
        // with a macro identifier whose value is a known non-absolute path.
        // Used alongside `has_env03_taint_source` to prevent caller-aware
        // suppression from masking CWE-426 sinks.
        if !string_macros.is_empty() {
            summary.has_relative_command_write =
                body_has_relative_command_write(&body, source, string_macros);
        }

        // Seed return-value taint: a function that directly calls a taint
        // source and returns non-void may carry that taint back to callers.
        // Refined in the cross-function fixpoint pass.
        if !is_void_return {
            summary.returns_tainted = summary.has_env03_taint_source;
        }

        // Collect callees whose returns flow directly to this function's
        // return statements. Consumed by `propagate_return_taint` after all
        // summaries are computed.
        collect_returns_from_callees(&body, source, &mut summary.returns_from_callees);

        // Check for NULL return
        if !summary.can_return_null {
            // Even non-pointer return types: check if the function returns NULL
            summary.can_return_null = check_returns_null(&body, source);
        }

        // For pointer-returning functions: if every return statement provably
        // returns a non-null value (e.g. `return &s_switches`), clear the
        // pessimistic can_return_null flag set above.
        if is_pointer_return && summary.can_return_null {
            if check_all_returns_nonnull(&body, source) {
                summary.can_return_null = false;
            }
        }

        // Analyze parameter usage
        let sweep = BodySweep::of(&body);
        analyze_param_usage(
            &body,
            &sweep,
            source,
            body_text,
            &params,
            function_macros,
            &mut summary,
        );
        let arms = crate::analyze::dead_regions::arm_assumptions(func_node, source);
        for &idx in &summary.frees_params {
            summary.free_arms.entry(idx).or_default().push(arms.clone());
        }
        credit_clears_params(&sweep.calls, source, &params, clearing_names, &mut summary);

        // Compute return value range for integer-returning functions (only when VRA is needed)
        if compute_return_ranges && !is_void_return && !is_pointer_return {
            summary.return_range = compute_return_range(&body, source, macros);
            summary.returns_only_compile_time_constants =
                returns_only_compile_time_constants(&body, source, macros);
        }

        // Only a pointer-returning function can hand a written-into
        // parameter back to its caller by value (Juliet's "source relay"
        // pattern: `data = someSource(data)`) — a void function's writes
        // to a parameter are visible through the pointer itself, not this
        // summary.
        if is_pointer_return {
            summary.produces_param_buffer_size =
                compute_produces_param_buffer_size(&body, source, &params, macros);
        }
    }

    summary
}

/// For each parameter, the largest buffer size or memset-fill content length
/// this function itself writes into it — directly, or through one local
/// alias hop (`char *buf = malloc(...); data = buf;`) — before returning.
/// See [`FunctionSummary::produces_param_buffer_size`].
fn compute_produces_param_buffer_size(
    body: &Node,
    source: &str,
    params: &[String],
    macros: &MacroConstantMap,
) -> HashMap<usize, usize> {
    let start = body.start_position().row;
    let end = body.end_position().row;
    let mut result = HashMap::new();
    for (idx, param_name) in params.iter().enumerate() {
        if let Some(size) = produced_size_for_var(param_name, body, source, start, end, macros) {
            result.insert(idx, size);
            continue;
        }
        if let Some(alias) =
            crate::analyze::buffer_size::resolve_bare_alias_in_range(param_name, source, start, end)
        {
            if let Some(size) = produced_size_for_var(&alias, body, source, start, end, macros) {
                result.insert(idx, size);
            }
        }
    }
    result
}

/// Combine every buffer-size resolver a relay function's own body can prove
/// a variable safe under, within an explicit row range: allocation size,
/// memset-fill content length, a fixed array declaration's element count, or
/// a strlen/wcslen-derived allocation. Only one is ever meaningful for a
/// given relay function in practice, so whichever resolves first is the
/// answer. Mirrors the resolver chain `Str31C::find_buffer_size` uses for
/// its own same-file relay lookup — kept in lock-step so the
/// same-file and cross-file relay-resolution paths stay equally capable.
fn produced_size_for_var(
    var_name: &str,
    body: &Node,
    source: &str,
    start: usize,
    end: usize,
    macros: &MacroConstantMap,
) -> Option<usize> {
    crate::analyze::buffer_size::resolve_alloc_assigned_in_range(var_name, source, start, end)
        .or_else(|| {
            crate::analyze::buffer_size::memset_content_length_in_range(
                var_name,
                source,
                start,
                end + 1,
            )
        })
        .or_else(|| {
            crate::analyze::array_size::resolve_declared_array_size(body, var_name, source, macros)
        })
        .or_else(|| {
            let lines: Vec<&str> = source.lines().collect();
            crate::analyze::buffer_size::resolve_strlen_based_alloc_size(
                var_name, &lines, start, end,
            )
        })
}

/// The number of fixed parameters before a trailing `...`, or `None` when
/// `func_node`'s declarator has no `variadic_parameter`. See
/// `FunctionSummary::variadic_from`.
fn detect_variadic_arity(func_node: &Node) -> Option<usize> {
    let declarator = func_node.child_by_field_name("declarator")?;
    find_variadic_arity_in_declarator(&declarator)
}

fn find_variadic_arity_in_declarator(node: &Node) -> Option<usize> {
    if node.kind() == "function_declarator" {
        let param_list = node.child_by_field_name("parameters")?;
        let mut fixed = 0usize;
        for i in 0..param_list.child_count() {
            let child = param_list.child(i)?;
            match child.kind() {
                "parameter_declaration" => fixed += 1,
                "variadic_parameter" => return Some(fixed),
                _ => {}
            }
        }
        None
    } else {
        node.child_by_field_name("declarator")
            .and_then(|d| find_variadic_arity_in_declarator(&d))
    }
}

/// See [`FunctionSummary::declares_no_params`].
fn declares_no_params(func_node: &Node, source: &str) -> bool {
    let Some(mut node) = func_node.child_by_field_name("declarator") else {
        return false;
    };
    while node.kind() != "function_declarator" {
        match node.child_by_field_name("declarator") {
            Some(inner) => node = inner,
            None => return false,
        }
    }
    // A function returning a function pointer nests a second parameter list;
    // which one is the definition's own is not worth guessing at here.
    if node.child_by_field_name("declarator").is_some_and(|d| {
        !lang_parsing_substrate::query::find_descendants_of_kind(d, "function_declarator")
            .is_empty()
    }) {
        return false;
    }
    let Some(params) = node.child_by_field_name("parameters") else {
        return false;
    };
    let mut cursor = params.walk();
    let entries: Vec<Node> = params
        .named_children(&mut cursor)
        .filter(|c| c.kind() != "comment")
        .collect();
    match entries.as_slice() {
        [] => true,
        [only] => {
            only.kind() == "parameter_declaration"
                && only.child_by_field_name("declarator").is_none()
                && only
                    .child_by_field_name("type")
                    .is_some_and(|t| t.utf8_text(source.as_bytes()) == Ok("void"))
                && only.named_child_count() == 1
        }
        _ => false,
    }
}

/// Whether every value that can reach `name`'s parameters provably comes from
/// callers `is_clean` accepts -- the caller-side proof of ADR-0011, walked up
/// the reverse call graph (`callers`, as `ProjectContext::callers` holds it).
///
/// `name` itself needs a closed caller set
/// ([`FunctionSummary::caller_set_is_closed`]) and at least one caller. Each
/// caller on the way up must pass `is_clean`. A caller that declares no
/// parameters ends its branch: nothing its own callers pass can reach it. Any
/// other caller forwards whatever reached it, so the proof needs the same of
/// it in turn -- a closed caller set and at least one caller -- until every
/// branch ends in a parameterless function. An exported relay, a static relay
/// whose address escapes, or `main` (open, and handed `argv`) ends the proof,
/// which is what a relay one hop up (`void api(char *s) { sink(s); }`) needs:
/// the sink's only caller is clean-bodied, but `s` comes from outside.
/// A caller with no summary ends it the same way.
pub fn every_caller_is_clean(
    name: &str,
    callers: &HashMap<String, HashSet<String>>,
    summaries: &(impl crate::analyze::context::SummaryLookup + ?Sized),
    is_clean: impl Fn(&FunctionSummary) -> bool,
) -> bool {
    let closed_with_callers = |fname: &str| -> Option<Vec<String>> {
        let own = summaries.get(fname)?;
        if !own.caller_set_is_closed() {
            return None;
        }
        let cs = callers.get(fname).filter(|cs| !cs.is_empty())?;
        Some(cs.iter().cloned().collect())
    };
    let Some(mut stack) = closed_with_callers(name) else {
        return false;
    };
    let mut visited: HashSet<String> = HashSet::from([name.to_string()]);
    while let Some(current) = stack.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        let Some(summary) = summaries.get(&current) else {
            return false;
        };
        if !is_clean(summary) {
            return false;
        }
        if summary.declares_no_params {
            continue;
        }
        let Some(up) = closed_with_callers(&current) else {
            return false;
        };
        stack.extend(up.into_iter().filter(|c| !visited.contains(c)));
    }
    true
}

/// Collect parameter names from a function declaration.
pub fn collect_param_names(func_node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(declarator) = func_node.child_by_field_name("declarator") {
        collect_params_recursive(&declarator, source, &mut params);
    }

    params
}

/// Walk a function's top-level declarator chain to determine whether the
/// function's *return type* is a pointer, without descending into the
/// parameter list (where `pointer_declarator`/`*` from an argument type
/// would otherwise be mistaken for the return type's own pointer-ness).
/// `T *foo(...)` parses as `pointer_declarator(declarator: function_declarator(...))`;
/// `T foo(...)` parses as a bare `function_declarator`; multi-level pointers
/// and parenthesized declarators nest further before reaching either.
fn declarator_denotes_pointer_return(declarator: &Node) -> bool {
    let mut node = *declarator;
    loop {
        match node.kind() {
            "pointer_declarator" => return true,
            "function_declarator" => return false,
            _ => match node.child_by_field_name("declarator") {
                Some(inner) => node = inner,
                None => return false,
            },
        }
    }
}

fn collect_params_recursive(node: &Node, source: &str, params: &mut Vec<String>) {
    if node.kind() == "function_declarator" {
        if let Some(param_list) = node.child_by_field_name("parameters") {
            for i in 0..param_list.child_count() {
                if let Some(param) = param_list.child(i) {
                    if param.kind() == "parameter_declaration" {
                        if let Some(decl) = param.child_by_field_name("declarator") {
                            let name = extract_leaf_identifier(&decl, source);
                            params.push(name);
                        } else {
                            params.push(String::new()); // Unnamed parameter
                        }
                    }
                }
            }
        }
    } else {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                collect_params_recursive(&child, source, params);
            }
        }
    }
}
/// Does some `return` in `body` hand back memory an allocator produced?
///
/// `Some(true)` when a returned expression, cast and parentheses
/// peeled, is a call to an allocator or names something assigned from one
/// (`p = malloc(n); ... return p;`, through plain identifier copies so
/// `nbuf = realloc(p, n); p = nbuf; return p;` still counts, either arm of
/// a `?:`, and an offset off the block -- `return a + 1`, hostap's traced
/// os_malloc handing back the block past its bookkeeping header).
/// `Some(false)` when every return flows from something else --
/// a cursor into a caller's buffer, a parameter, a field of the argument --
/// however many allocations the body makes and frees on the way. `None`
/// when the body's parse recovered no `return` statement inside the
/// boundary at all, which is the one case a text scan is still the better
/// witness.
///
/// "Allocator" keeps the substring reach of the scan this replaces: any
/// callee whose spelling contains `malloc`/`calloc`/`realloc`/
/// `aligned_alloc`, so `os_realloc` and `curlx_calloc` qualify exactly as
/// before. What changed is only that the call has to reach the return.
///
/// `text_end` is the same nested-function boundary the text scan honours:
/// a sibling definition tree-sitter swallowed into this body stays
/// outside, and a genuine nested `function_definition` node is never
/// entered.
fn is_allocator_name(name: &str) -> bool {
    name.contains("malloc")
        || name.contains("calloc")
        || name.contains("realloc")
        || name.contains("aligned_alloc")
}

fn body_returned_callees(body: &Node, source: &str, text_end: usize) -> Option<HashSet<String>> {
    fn lvalue_name(node: &Node, source: &str) -> Option<String> {
        // A declarator's `*` prefixes name nothing; peel to the identifier.
        let mut n = *node;
        while n.kind() == "pointer_declarator" || n.kind() == "parenthesized_declarator" {
            n = n.child_by_field_name("declarator").or_else(|| n.child(1))?;
        }
        match n.kind() {
            "identifier" | "field_expression" => {
                Some(n.utf8_text(source.as_bytes()).ok()?.trim().to_string())
            }
            _ => None,
        }
    }
    // One pass: every plain `lhs = rhs` and `T lhs = rhs`, plus every return.
    fn collect<'a>(
        node: Node<'a>,
        source: &str,
        text_end: usize,
        pairs: &mut Vec<(String, Node<'a>)>,
        returns: &mut Vec<Node<'a>>,
    ) {
        if node.start_byte() >= text_end || node.kind() == "function_definition" {
            return;
        }
        match node.kind() {
            "assignment_expression" => {
                let plain = node
                    .child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "=");
                if let (true, Some(l), Some(r)) = (
                    plain,
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if let Some(name) = lvalue_name(&l, source) {
                        pairs.push((name, r));
                    }
                }
            }
            "init_declarator" => {
                if let (Some(d), Some(v)) = (
                    node.child_by_field_name("declarator"),
                    node.child_by_field_name("value"),
                ) {
                    if let Some(name) = lvalue_name(&d, source) {
                        pairs.push((name, v));
                    }
                }
            }
            "return_statement" => returns.push(node),
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            collect(child, source, text_end, pairs, returns);
        }
    }
    let mut pairs: Vec<(String, Node)> = Vec::new();
    let mut returns: Vec<Node> = Vec::new();
    collect(*body, source, text_end, &mut pairs, &mut returns);
    if returns.is_empty() {
        return None;
    }

    /// The callees whose results `expr` may carry: the call itself; what a
    /// name was assigned from; either arm of a `?:`; the left operand of an
    /// offset. Casts and parentheses are peeled first.
    fn expr_sources(
        expr: &Node,
        source: &str,
        sources: &HashMap<String, HashSet<String>>,
    ) -> HashSet<String> {
        let e = init_state::strip_arg_casts(expr);
        match e.kind() {
            "call_expression" => e
                .child_by_field_name("function")
                .filter(|f| f.kind() == "identifier")
                .map(|f| f.utf8_text(source.as_bytes()).unwrap_or("").to_string())
                .into_iter()
                .collect(),
            "identifier" | "field_expression" => sources
                .get(e.utf8_text(source.as_bytes()).unwrap_or("").trim())
                .cloned()
                .unwrap_or_default(),
            "conditional_expression" => ["consequence", "alternative"]
                .iter()
                .filter_map(|f| e.child_by_field_name(f))
                .flat_map(|a| expr_sources(&a, source, sources))
                .collect(),
            "binary_expression" => {
                let op = e
                    .child_by_field_name("operator")
                    .map(|o| o.kind())
                    .unwrap_or("");
                match e.child_by_field_name("left") {
                    Some(l) if op == "+" || op == "-" => expr_sources(&l, source, sources),
                    _ => HashSet::new(),
                }
            }
            _ => HashSet::new(),
        }
    }

    // Which callees each name may hold the result of, through however many
    // plain copies: `nbuf = realloc(p, n); p = nbuf;` and curl's
    // `buf = (len < SIZE_MAX) ? curlx_malloc(len + 1) : NULL;` alike.
    let mut sources: HashMap<String, HashSet<String>> = HashMap::new();
    loop {
        let mut grew = false;
        for (name, rhs) in &pairs {
            let found = expr_sources(rhs, source, &sources);
            if found.is_empty() {
                continue;
            }
            let entry = sources.entry(name.clone()).or_default();
            let before = entry.len();
            entry.extend(found);
            grew |= entry.len() != before;
        }
        if !grew {
            break;
        }
    }

    let returned: HashSet<String> = returns
        .iter()
        .flat_map(|ret| {
            (0..ret.child_count())
                .filter_map(|i| ret.child(i))
                .filter(|c| c.is_named())
                .flat_map(|expr| expr_sources(&expr, source, &sources))
                .collect::<Vec<_>>()
        })
        .collect();
    Some(returned)
}

/// Strip `/* ... */` and `// ...` comments from a (possibly multi-line)
/// function body before a plain substring scan. Without this, a comment
/// merely *mentioning* an allocator call -- e.g. sqlite's own
/// `sqlite3_column_blob`, whose body has no `malloc()` call at all but a
/// doc comment reading "might need to call malloc() to expand the result of
/// a zeroblob()" -- makes `returns_allocation`'s substring check below
/// misfire on a borrowed-accessor function that never allocates anything
/// . Unlike `macro_expand::strip_comments` (single-line macro
/// replacement lists, where hitting `//` means "rest of the line is gone"),
/// this must span a whole multi-line function body: a `//` only blanks out
/// to the next newline, not to the end of the text.
fn strip_comments_multiline(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            out.push(' ');
        } else if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Blank out the contents of `"..."` and `'...'` literals (dropped
/// entirely, not replaced char-for-char, since callers only need a
/// substring scan over what remains, not aligned positions) so a plain text
/// scan over a function's body does not treat a string constant that merely
/// NAMES a function -- `"usage: getenv(VAR)"` -- as a real call to it.
///
/// Must run AFTER `strip_comments_multiline`: a stray quote inside a
/// comment (`// see "getenv(" usage below`) would otherwise make this walk
/// think it's inside a string literal for the rest of the body, silently
/// dropping real code that follows.
fn strip_string_literals(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            out.push(' ');
            i += 1;
            while i < chars.len() && chars[i] != c {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if i < chars.len() {
                i += 1; // consume the closing quote
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Check if a function body always calls abort/exit/longjmp (never returns normally).
fn check_never_returns(body_text: &str) -> bool {
    // Quick text check — if none of these are present, the function can return
    if !body_text.contains("abort(")
        && !body_text.contains("exit(")
        && !body_text.contains("_Exit(")
        && !body_text.contains("longjmp(")
        && !body_text.contains("quick_exit(")
    {
        return false;
    }

    // More precise: check if every code path ends with a no-return call.
    // For simplicity, check if the function's body ends with a no-return call
    // (last statement is abort/exit/etc. — no return statement after it).
    let has_return = body_text.contains("return ");
    let ends_with_noreturn = body_text.contains("abort()")
        || body_text.contains("exit(EXIT_FAILURE)")
        || body_text.contains("exit(1)")
        || body_text.contains("exit(EXIT_SUCCESS)")
        || body_text.contains("exit(0)");

    // If the function has no return statements and ends with a no-return call
    if !has_return && ends_with_noreturn {
        return true;
    }

    // Simple heuristic: if every path through the function ends with
    // abort/exit, it never returns. This is too expensive to check fully
    // without a CFG, so we use a conservative approach.
    false
}

/// Check if a function body contains any `return NULL` / `return 0` statements.
/// Returns true when every `return` statement in `body` provably returns a non-null
/// value. Currently recognises `return &expr` (address-of — always non-null).
/// Returns false conservatively if ANY return path is not recognised as non-null,
/// or if there are no return statements.
fn check_all_returns_nonnull(body: &Node, source: &str) -> bool {
    let mut found_any = false;
    let result = check_returns_all_nonnull_recursive(body, source, &mut found_any);
    found_any && result
}

/// Recursive helper: returns (all_nonnull) and populates found_any.
fn check_returns_all_nonnull_recursive(node: &Node, source: &str, found_any: &mut bool) -> bool {
    if node.kind() == "return_statement" {
        *found_any = true;
        // Check if the returned value is provably non-null
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "return" || child.kind() == ";" {
                    continue;
                }
                // `return &expr` — address-of is always non-null
                if child.kind() == "pointer_expression" {
                    if let Some(op) = child.child_by_field_name("operator") {
                        if op.utf8_text(source.as_bytes()).unwrap_or("") == "&" {
                            return true;
                        }
                    }
                }
                // Text-level: `return &identifier`
                let text = child.utf8_text(source.as_bytes()).unwrap_or("").trim();
                if text.starts_with('&') {
                    return true;
                }
                return false;
            }
        }
        return false;
    }

    // Don't cross nested function definitions
    if node.kind() == "function_definition" {
        return true; // Neutral for parent's all-nonnull check
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if !check_returns_all_nonnull_recursive(&child, source, found_any) {
                return false;
            }
        }
    }
    true
}

fn check_returns_null(body: &Node, source: &str) -> bool {
    if body.kind() == "return_statement" {
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() != "return" {
                    let text = child.utf8_text(source.as_bytes()).unwrap_or("").trim();
                    if text == "NULL" || text == "0" || text == "nullptr" {
                        return true;
                    }
                }
            }
        }
    }

    for i in 0..body.child_count() {
        if let Some(child) = body.child(i) {
            // Don't cross into a nested (swallowed-sibling) function boundary.
            if is_real_nested_function_definition(&child, source) {
                continue;
            }
            if check_returns_null(&child, source) {
                return true;
            }
        }
    }

    false
}

/// True if `body_text` writes through `param_name` via a bare dereference
/// assignment, `*param_name = …`, tolerating an intervening `++`/`--`
/// (`*param_name++ = …`) between the identifier and the `=`. Excludes
/// comparison operators (`==`, `!=`, `<=`, `>=`) the same way the plain
/// `*param =` check historically did.
///
/// The walking-pointer buffer-fill idiom this exists for --
/// `*rnd++ = (unsigned char)(r & 0xFF);` -- is curl's `Curl_rand_bytes`
/// (this only
/// pays off once the forwarded function's own summary actually recognizes
/// its write). A literal `"*{param} ="` substring match (the previous
/// check) misses this because of the `++` in between.
fn body_has_deref_write(body_text: &str, param_name: &str) -> bool {
    let pattern = format!("*{param_name}");
    let mut search_from = 0;
    while let Some(rel) = body_text[search_from..].find(&pattern) {
        let pos = search_from + rel;
        let after = pos + pattern.len();
        search_from = after;
        let rest = body_text[after..].trim_start();
        let rest = rest
            .strip_prefix("++")
            .or_else(|| rest.strip_prefix("--"))
            .unwrap_or(rest)
            .trim_start();
        if let Some(after_eq) = rest.strip_prefix('=') {
            if !after_eq.starts_with('=') {
                return true;
            }
        }
    }
    false
}

/// True when `param_name` is dereferenced through a pointer cast --
/// `*(int *)param` (a `*` right before the cast) or `((int *)param)->field` /
/// `((int *)param)[i]` (the cast wrapped in an outer paren immediately
/// followed by `->`/`[`) -- as opposed to a cast merely used as a value, e.g.
/// `callee(x, (int *)param)` or `void *q = (int *)param;`.
///
/// A prior version matched the bare substring `"*){param}"`, which is
/// present in EVERY pointer cast of `param` regardless of what happens to
/// the cast result. That made a cast forwarding `param` as a plain call
/// argument look identical to a real dereference: curl's
/// `curlx_inet_pton(af, src, dst)` (built as a thin wrapper when the
/// platform lacks a real `inet_pton`) does
/// `return inet_pton4(src, (unsigned char *)dst);` -- a cast used only to
/// forward `dst` to a helper that `memcpy`-writes it, the textbook
/// output-parameter shape. The substring match alone put `dst` in
/// `dereferences_params`, and since nothing in this function directly
/// writes `dst` either (the write happens two calls deep, through
/// `inet_pton4`), `build_read_only_deref_fns` (EXP33-C) subtracted an empty
/// `modifies_params` and concluded `curlx_inet_pton` reads `dst` without
/// writing it -- backwards. Confirmed by reproduction, not just reading:
/// removing the cast, or removing the forward entirely, both removed the
/// finding.
fn cast_then_deref(body_text: &str, param_name: &str) -> bool {
    let needle = format!("*){param_name}");
    let bytes = body_text.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = body_text[search_from..].find(&needle) {
        let star_idx = search_from + rel;
        let close_paren = star_idx + 1; // the ')' right after the cast's '*'

        // Walk backward from the cast's ')' to its matching '(', balancing
        // any nested parens in the type name (e.g. a function-pointer cast).
        let mut depth = 1i32;
        let mut i = close_paren;
        let mut open_paren = None;
        while i > 0 {
            i -= 1;
            match bytes[i] {
                b')' => depth += 1,
                b'(' => {
                    depth -= 1;
                    if depth == 0 {
                        open_paren = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(open) = open_paren else {
            search_from = close_paren + 1;
            continue;
        };

        let preceded_by_star = body_text[..open].trim_end().ends_with('*');
        let after = &body_text[close_paren + 1 + param_name.len()..];
        let wrapped_deref = after.trim_start().strip_prefix(')').is_some_and(|rest| {
            let rest = rest.trim_start();
            rest.starts_with("->") || rest.starts_with('[')
        });
        if preceded_by_star || wrapped_deref {
            return true;
        }
        search_from = close_paren + 1;
    }
    false
}

/// True if `body_text` contains a genuine READ through `param_name->field`
/// -- i.e. at least one occurrence of `param_name->` that is not itself the
/// operand of an address-of expression. `&param->field` never reads the
/// field's value; it hands the field's address to whatever it's passed to,
/// typically a callee that writes through it: mbedtls's
/// `mbedtls_ecp_point_init(mbedtls_ecp_point *pt) { mbedtls_mpi_init(&pt->X);
/// mbedtls_mpi_init(&pt->Y); mbedtls_mpi_init(&pt->Z); }` never reads `pt`
/// at all, and crediting every one of these as a dereference-read
/// classified the whole `_init` family as read-only on their own output
/// parameter (see EXP33-C piece (d)). A function that
/// has both an address-of use and a genuine read elsewhere still counts:
/// this only withholds credit when EVERY occurrence is address-of'd.
fn has_genuine_arrow_read(body_text: &str, param_name: &str) -> bool {
    let needle = format!("{param_name}->");
    let mut search_from = 0usize;
    while let Some(rel) = body_text[search_from..].find(&needle) {
        let pos = search_from + rel;
        if !body_text[..pos].trim_end().ends_with('&') {
            return true;
        }
        search_from = pos + needle.len();
    }
    false
}

/// The locals initialised or assigned from a pointer cast of `param_name`
/// -- `char **p = (char **)param;` or `p = (char **)param;`.
///
/// The `void *` hand-off idiom: a callee takes `void *` and casts it back to
/// its real type in a local before using it (Juliet's `_64` sinks, any
/// callback taking a `void *` context, curl's hash-context initialisers).
/// What the callee does through such a local, it does to the caller's
/// object, so `analyze_param_usage` and `credit_modifies_params` credit the
/// alias's reads and writes to the parameter. `cast_then_deref` only sees the
/// cast dereferenced in place; before it was narrowed to that, the bare
/// substring `*)param` covered the aliased reads by accident (and nothing
/// covered the writes), and narrowing it silently dropped every such callee
/// out of `dereferences_params` (task 1502: MEM01-C's double free and
/// EXP33-C's uninitialised read through a `_64` sink both went dark).
///
/// A plain `T *p = param;` alias is deliberately not collected: it was never
/// credited, and widening to it is a separate measurement.
fn cast_aliases_of(body: &Node, source: &str, param_name: &str) -> Vec<String> {
    use crate::utility::cert_c::ast_utils;
    use lang_parsing_substrate::query;

    // A cast of the parameter, parentheses allowed: `(T *)param`, `((T *)param)`.
    let is_cast_of_param = |value: &Node| {
        let mut v = *value;
        while v.kind() == "parenthesized_expression" {
            match v.named_child(0) {
                Some(inner) => v = inner,
                None => return false,
            }
        }
        if v.kind() != "cast_expression" {
            return false;
        }
        let target = init_state::strip_arg_casts(&v);
        target.kind() == "identifier" && target.utf8_text(source.as_bytes()) == Ok(param_name)
    };

    let mut aliases: Vec<String> = Vec::new();
    for node in
        query::find_descendants_of_kinds(*body, &["init_declarator", "assignment_expression"])
    {
        let (lhs, value) = if node.kind() == "init_declarator" {
            let (Some(d), Some(v)) = (
                node.child_by_field_name("declarator"),
                node.child_by_field_name("value"),
            ) else {
                continue;
            };
            (ast_utils::get_identifier_from_declarator(&d, source), v)
        } else {
            let (Some(l), Some(v)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                continue;
            };
            let plain_assign = node
                .child_by_field_name("operator")
                .and_then(|o| o.utf8_text(source.as_bytes()).ok())
                == Some("=");
            if l.kind() != "identifier" || !plain_assign {
                continue;
            }
            (l.utf8_text(source.as_bytes()).unwrap_or("").to_string(), v)
        };
        if !lhs.is_empty()
            && lhs != param_name
            && is_cast_of_param(&value)
            && !aliases.contains(&lhs)
        {
            aliases.push(lhs);
        }
    }
    aliases
}

/// The accesses in `body` that dereference the local `alias` -- `*alias`,
/// `alias->f`, `alias[i]` -- other than to take an address: `&alias->f` and
/// `&alias[i]` name storage without touching it, the same exclusion
/// `has_genuine_arrow_read` makes for a parameter (curl's
/// `sa6 = (void *)ss; curlx_inet_pton(AF_INET6, s, &sa6->sin6_addr)` hands
/// the field to a writer and reads nothing). Asked of the AST: the body-text
/// `*name` check would also match the alias's own declarator.
fn alias_derefs<'a>(body: &Node<'a>, source: &str, alias: &str) -> Vec<Node<'a>> {
    use lang_parsing_substrate::query;

    query::find_descendants_of_kinds(
        *body,
        &[
            "field_expression",
            "pointer_expression",
            "subscript_expression",
        ],
    )
    .into_iter()
    .filter(|n| {
        let base = match n.kind() {
            "field_expression" => {
                let arrow = n
                    .child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "->");
                if !arrow {
                    return false;
                }
                n.child_by_field_name("argument")
            }
            "pointer_expression" => {
                if n.child(0).map(|c| c.kind()) != Some("*") {
                    return false;
                }
                n.child_by_field_name("argument")
            }
            _ => n.child_by_field_name("argument"),
        };
        let rooted = base.is_some_and(|b| {
            b.kind() == "identifier" && b.utf8_text(source.as_bytes()) == Ok(alias)
        });
        rooted && !is_address_taken(n) && !is_unevaluated(n)
    })
    .collect()
}

/// Whether `param_name`'s cast aliases are null-checked at all, and whether
/// one is null-checked before anything dereferences it: `(checked,
/// checked_before_deref)`, the alias half of `checks_null_params` /
/// `checks_null_params_before_deref`.
///
/// Crediting an alias's dereference to its parameter (`cast_aliases_of`)
/// without crediting its guard made the guarded wrapper look unguarded:
/// sqlite's `Vdbe *p = (Vdbe *)pStmt; if( p==0 ) return ...; p->rc` put
/// `pStmt` in `dereferences_params` with no null check, and API00-C fired on
/// every public entry point forwarding to it. `body_matches_alias_null_check`
/// cannot see this alias (it looks for `= param`, not `= (T *)param`), and
/// `first_deref_offset` counts the cast text `*)param` itself as the first
/// dereference, which cuts off every guard after it.
///
/// "Before" is measured against the alias's own first dereference and the
/// parameter's own first DIRECT one (`*param`, `param->`, `param[`) -- not
/// the cast, which is where the alias comes from -- so a raw use of the
/// parameter ahead of the alias's guard is still an unguarded use.
fn alias_null_checks(
    body: &Node,
    source: &str,
    body_text: &str,
    param_name: &str,
    aliases: &[String],
) -> (bool, bool) {
    let direct_param_deref = [
        format!("*{param_name}"),
        format!("{param_name}->"),
        format!("{param_name}["),
    ]
    .iter()
    .filter_map(|pattern| body_text.find(pattern.as_str()))
    .min();

    let mut checked = false;
    let mut before = false;
    for alias in aliases {
        if !body_matches_null_check(body_text, alias) {
            continue;
        }
        checked = true;
        let first_alias_deref = alias_derefs(body, source, alias)
            .iter()
            .map(|n| n.start_byte().saturating_sub(body.start_byte()))
            .min();
        let cut = [first_alias_deref, direct_param_deref]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(body_text.len())
            .min(body_text.len());
        if body_matches_null_check(&body_text[..cut], alias) {
            before = true;
        }
    }
    (checked, before)
}

/// True when `node` sits in an operand C never evaluates -- `sizeof`,
/// `_Alignof`, `offsetof` -- so `sizeof(*hdr)` reads nothing. hostap's
/// `if (len < sizeof(*hdr) + ...)` length checks put exactly that shape
/// ahead of an alias's real accesses, and before this it was the ONLY
/// "dereference" of `hdr` in `ieee802_1x_tx_status`.
fn is_unevaluated(node: &Node) -> bool {
    use crate::utility::cert_c::ast_utils;
    use lang_parsing_substrate::query;

    ast_utils::is_in_sizeof(node)
        || query::find_ancestor(*node, |a| {
            matches!(a.kind(), "alignof_expression" | "offsetof_expression")
        })
        .is_some()
}

/// True when `access` (`p->f`, `p[i]`) is only the operand of an
/// address-of, possibly through further `.field` selections, subscripts and
/// parentheses: `&p->f`, `&p->f.g`, `&p->buf[0]`, `&(p[i])`. The same
/// reach as `has_genuine_arrow_read`'s text test for a parameter, which
/// treats any `&` directly before `param->` as address-of.
fn is_address_taken(access: &Node) -> bool {
    let mut cur = *access;
    while let Some(parent) = cur.parent() {
        match parent.kind() {
            "parenthesized_expression" => cur = parent,
            "subscript_expression" if parent.child_by_field_name("argument") == Some(cur) => {
                cur = parent
            }
            "field_expression"
                if parent.child_by_field_name("argument") == Some(cur)
                    && parent
                        .child_by_field_name("operator")
                        .is_some_and(|op| op.kind() == ".") =>
            {
                cur = parent
            }
            "pointer_expression" => return parent.child(0).map(|c| c.kind()) == Some("&"),
            _ => return false,
        }
    }
    false
}

/// True when an assignment or `++`/`--` in `sweep` writes THROUGH the local
/// `alias` (`alias->f = v`, `*alias = v`, `alias[i]++`), by the same
/// `deref_write_root` test `credit_modifies_params` applies to a parameter.
fn alias_written_through(sweep: &BodySweep, source: &str, alias: &str) -> bool {
    let root_is_alias = |root: Node| root.utf8_text(source.as_bytes()) == Ok(alias);
    sweep.assignments.iter().any(|node| {
        node.child_by_field_name("left")
            .and_then(|left| deref_write_root(&left, false))
            .is_some_and(root_is_alias)
    }) || sweep.updates.iter().any(|node| {
        node.child_by_field_name("argument")
            .and_then(|argument| deref_write_root(&argument, false))
            .is_some_and(root_is_alias)
    })
}

/// Analyze how parameters are used in the function body. `body_text` may be
/// a boundary-truncated slice of `body`'s source (see `analyze_function`);
/// `collect_param_passthroughs` walks `body` itself and applies its own
/// nested-function boundary guard independently.
/// True if some line in `body_text` writes through `param_name` via
/// `param_name->...` or `param_name[...]` -- i.e. the arrow/subscript access
/// is followed by a genuine assignment operator (not `==`/`!=`/`<=`/`>=`) on
/// the same line. A bare `param_name->field` or `param_name[i]` with no
/// following `=` is a READ, not a write (see modifies_params call site).
fn line_has_arrow_or_subscript_write(body_text: &str, param_name: &str) -> bool {
    let arrow_pattern = format!("{}->", param_name);
    let subscript_pattern = format!("{}[", param_name);
    for line in body_text.lines() {
        let access_pos = line
            .find(&arrow_pattern)
            .or_else(|| line.find(&subscript_pattern));
        let Some(access_pos) = access_pos else {
            continue;
        };
        // Find an `=` after the access that isn't part of ==, !=, <=, >=.
        let after_access = &line[access_pos..];
        let mut search_from = 0;
        while let Some(rel_eq) = after_access[search_from..].find('=') {
            let eq_pos = search_from + rel_eq;
            let before = &after_access[..eq_pos];
            let after = &after_access[eq_pos + 1..];
            let is_comparison = before.ends_with('!')
                || before.ends_with('<')
                || before.ends_with('>')
                || before.ends_with('=')
                || after.starts_with('=');
            if !is_comparison {
                return true;
            }
            search_from = eq_pos + 1;
        }
    }
    false
}

/// True if `node` is unconditionally reached whenever `body` (the enclosing
/// function's own compound_statement) is entered — i.e. no ancestor between
/// `node` and `body` is a construct that might not execute (an `if`/`switch`
/// arm, a loop body that could run zero times, a ternary branch, or a
/// preprocessor conditional). Plain nested `{ }` scoping blocks are
/// transparent (still unconditional). Used to distinguish a MUST-free from
/// a merely-possible MAY-free.
fn is_unconditionally_reached(node: &Node, body: &Node) -> bool {
    let mut current = *node;
    loop {
        let Some(parent) = current.parent() else {
            return true;
        };
        if parent.id() == body.id() {
            return true;
        }
        if matches!(
            parent.kind(),
            "if_statement"
                | "switch_statement"
                | "case_statement"
                | "conditional_expression"
                | "for_statement"
                | "while_statement"
                | "do_statement"
        ) || parent.kind().starts_with("preproc_if")
        {
            return false;
        }
        current = parent;
    }
}

/// Whether `condition` is EXACTLY a null test of `name` and nothing else,
/// reporting which branch is the one on which `name` is non-null:
/// `Some(true)` when that is the consequence, `Some(false)` when it is the
/// `else`.
///
/// Deliberately narrower than `null_state`'s condition parser, which unions
/// the operands of `&&` and `||`. Here a compound condition must yield
/// `None`: `if (ptr && ready)` guards its body on something this frame knows
/// nothing about, and treating it as a bare null check is exactly the
/// over-trust that made MAY-frees unusable.
fn null_guard_on(condition: &Node, source: &str, name: &str) -> Option<bool> {
    let text = |n: &Node| n.utf8_text(source.as_bytes()).unwrap_or("").trim();
    let is_null_literal = |n: &Node| matches!(text(n), "NULL" | "0" | "nullptr");
    let is_name = |n: &Node| n.kind() == "identifier" && text(n) == name;

    match condition.kind() {
        "parenthesized_expression" => null_guard_on(&condition.child(1)?, source, name),
        "identifier" => is_name(condition).then_some(true),
        "unary_expression" => {
            let operator = condition.child(0)?;
            let argument = condition.child_by_field_name("argument")?;
            (text(&operator) == "!" && is_name(&argument)).then_some(false)
        }
        "binary_expression" => {
            let left = condition.child_by_field_name("left")?;
            let right = condition.child_by_field_name("right")?;
            let operator = condition.child_by_field_name("operator")?;
            let compares_name = (is_name(&left) && is_null_literal(&right))
                || (is_null_literal(&left) && is_name(&right));
            if !compares_name {
                return None;
            }
            match text(&operator) {
                "!=" => Some(true),
                "==" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

/// `is_unconditionally_reached`, except that an `if` guarding only on whether
/// `guarded` is null is transparent.
///
/// A free reached solely under `if (ptr != NULL)` — or in the `else` of
/// `if (ptr == NULL)` — is effectively a MUST-free: on the branch that skips
/// it there is nothing to free, so nothing survives the call for the caller
/// to use. Marking the argument freed therefore cannot invent a
/// use-after-free, which is the failure the MUST set exists to prevent
/// .
///
/// The guard must be on the pointer being freed and on nothing else. Any
/// other condition — a different variable, a flag, a compound test — is a
/// real MAY-free and reinstates an earlier fix's answer, because there the skipped
/// path can leave a live pointer the caller goes on to use.
fn is_unconditionally_reached_modulo_null_guard(
    node: &Node,
    body: &Node,
    source: &str,
    guarded: &str,
) -> bool {
    let mut current = *node;
    loop {
        let Some(parent) = current.parent() else {
            return true;
        };
        if parent.id() == body.id() {
            return true;
        }
        if parent.kind() == "if_statement" {
            let Some(condition) = parent.child_by_field_name("condition") else {
                return false;
            };
            let Some(non_null_on_true) = null_guard_on(&condition, source, guarded) else {
                return false;
            };
            // Which arm did the walk come up through? `alternative` is the
            // `else_clause` wrapper, so an identity test against both fields
            // answers it without assuming either is present.
            let from = |field: &str| {
                parent
                    .child_by_field_name(field)
                    .is_some_and(|arm| arm.id() == current.id())
            };
            let reached_when_non_null = if from("consequence") {
                non_null_on_true
            } else if from("alternative") {
                !non_null_on_true
            } else {
                // The condition itself, or some other child: not an arm.
                return false;
            };
            if !reached_when_non_null {
                return false;
            }
        } else if matches!(
            parent.kind(),
            "switch_statement"
                | "case_statement"
                | "conditional_expression"
                | "for_statement"
                | "while_statement"
                | "do_statement"
        ) || parent.kind().starts_with("preproc_if")
        {
            return false;
        }
        current = parent;
    }
}

/// Reduce a `free()` argument to the identifier it releases, reporting whether
/// the release goes through the identifier's pointee.
///
/// `free(p)` yields `(p, false)`; `free(*p)` and `free((*p))` yield `(p, true)`
/// — the `void **` "safe free" wrapper shape. Parentheses and casts are
/// transparent, so `free((char *) *p)` still resolves. Anything else (a field,
/// a subscript, a call) yields `None`.
fn strip_free_argument(arg: Node) -> Option<(Node, bool)> {
    fn peel(mut n: Node) -> Node {
        loop {
            let inner = match n.kind() {
                "parenthesized_expression" => n.named_child(0),
                "cast_expression" => n.child_by_field_name("value"),
                _ => None,
            };
            match inner {
                Some(i) => n = i,
                None => return n,
            }
        }
    }

    let node = peel(arg);
    if node.kind() == "identifier" {
        return Some((node, false));
    }
    if node.kind() == "pointer_expression" {
        let op = node.child_by_field_name("operator")?;
        if op.kind() != "*" {
            return None;
        }
        let inner = peel(node.child_by_field_name("argument")?);
        if inner.kind() == "identifier" {
            return Some((inner, true));
        }
    }
    None
}

/// Credit `summary.frees_params` (MAY-free) and `summary.
/// unconditional_frees_params` (MUST-free) for every `free(param)` call in
/// `body` whose sole argument is exactly one of `params` by simple
/// identifier — AST-based rather than the old text-substring scan so
/// `is_unconditionally_reached` can be checked per call site.
/// The parameter-rooted lvalue an assignment writes THROUGH, if any.
///
/// `*p`, `p->f`, `p[i]`, `(*p).f` and `*p++` all write to storage the caller
/// owns; a bare `p = ...` rebinds the local copy of the pointer and writes
/// nothing the caller can observe, which is why a dereference has to be seen
/// somewhere on the path before the root identifier counts.
fn deref_write_root<'a>(lvalue: &Node<'a>, saw_deref: bool) -> Option<Node<'a>> {
    match lvalue.kind() {
        "identifier" => saw_deref.then_some(*lvalue),
        "parenthesized_expression" => deref_write_root(&lvalue.child(1)?, saw_deref),
        "cast_expression" => deref_write_root(&lvalue.child_by_field_name("value")?, saw_deref),
        "update_expression" => {
            deref_write_root(&lvalue.child_by_field_name("argument")?, saw_deref)
        }
        "pointer_expression" => {
            let operator = lvalue.child(0)?;
            let is_deref = operator.kind() == "*";
            deref_write_root(
                &lvalue.child_by_field_name("argument")?,
                saw_deref || is_deref,
            )
        }
        "subscript_expression" => deref_write_root(&lvalue.child_by_field_name("argument")?, true),
        "field_expression" => {
            // `p->f` dereferences p; `s.f` does not, and only reaches a
            // parameter's storage if something below it did.
            let arrow = lvalue
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "->");
            deref_write_root(&lvalue.child_by_field_name("argument")?, saw_deref || arrow)
        }
        _ => None,
    }
}

/// The parameter-rooted objects a call writes through by virtue of being a
/// known initializing library function: `memset(e, 0, sizeof(*e))` writes
/// `e`, `os_memcpy(e->buf, src, n)` writes `e`.
///
/// `modifies_params`' three existing detectors (`body_has_deref_write`,
/// `line_has_arrow_or_subscript_write`, `is_fd_set_macro_write`) all require
/// an ASSIGNMENT OPERATOR rooted at the parameter, so a callee whose entire
/// initialisation of its output is a memory-writing library call never entered
/// the map -- and `credit_modifies_params`, the MUST/MAY refinement and the
/// forwarded-write obligations are every one of them reached only from there.
/// hostap's `ieee802_11_parse_elems`, whose body is `os_memset(elems, 0, ...)`
/// and a forward, had 65 callers reported uninitialised on that account.
///
/// Name-independent by construction: resolution is
/// `init_state::match_initializing_function`, whose suffix matcher is what
/// turns `os_memset` into `memset`, over that module's own output-index
/// tables. Nothing here carries a second list to disagree with them.
fn library_written_roots<'a>(call: &Node<'a>, source: &str) -> Vec<Node<'a>> {
    let mut roots = Vec::new();
    let Some(func) = call.child_by_field_name("function") else {
        return roots;
    };
    let func_name = func.utf8_text(source.as_bytes()).unwrap_or("");
    let Some(base) = init_state::match_initializing_function(func_name) else {
        return roots;
    };
    // `regexec`/`mbrlen` and friends are listed as initializers but read
    // through their pointer arguments; that judgement lives in one place.
    if init_state::is_non_initializing_function(base) {
        return roots;
    }
    let indices = init_state::get_output_arg_indices(base);
    let variadic_from = init_state::variadic_output_from_index(base);
    let Some(args) = call.child_by_field_name("arguments") else {
        return roots;
    };
    let mut arg_idx = 0usize;
    for i in 0..args.child_count() {
        let Some(arg) = args.child(i) else { continue };
        if matches!(arg.kind(), "," | "(" | ")") {
            continue;
        }
        let is_output =
            indices.contains(&arg_idx) || variadic_from.is_some_and(|first| arg_idx >= first);
        if is_output {
            if let Some(root) = written_arg_root(&arg) {
                roots.push(root);
            }
        }
        arg_idx += 1;
    }
    roots
}

/// The object an output argument writes through, when it reaches storage the
/// CALLER owns.
///
/// A bare `e` counts: handing the pointer over is itself the dereference.
/// Below that, `deref_write_root` decides, so this draws exactly the line an
/// assignment already does and cannot drift from it -- `e->buf` and `e[i]`
/// count, `&e.f` does not.
fn written_arg_root<'a>(arg: &Node<'a>) -> Option<Node<'a>> {
    match arg.kind() {
        "identifier" => Some(*arg),
        "parenthesized_expression" => written_arg_root(&arg.child(1)?),
        "cast_expression" => written_arg_root(&arg.child_by_field_name("value")?),
        _ => deref_write_root(arg, false),
    }
}

/// Every name an initializing library call in `body` writes through. The
/// MAY-write half of `library_written_roots`; the MUST/MAY refinement is
/// `credit_modifies_params`' business, as it is for an assignment.
///
/// Returned as a set rather than answered per parameter, because the walk
/// costs the same whether one name or eight are being asked about and this
/// file has been the source of superlinear scan behaviour before.
fn library_written_names(body: &Node, source: &str) -> HashSet<String> {
    use lang_parsing_substrate::query;

    library_written_names_in(
        &query::find_descendants_of_kind(*body, "call_expression"),
        source,
    )
}

/// [`library_written_names`] over calls already collected from the body.
fn library_written_names_in(calls: &[Node], source: &str) -> HashSet<String> {
    calls
        .iter()
        .flat_map(|call| library_written_roots(call, source))
        .filter_map(|root| root.utf8_text(source.as_bytes()).ok().map(str::to_string))
        .collect()
}

/// The nodes of a function body that the per-parameter passes below keep
/// asking for, each in pre-order, collected in one walk.
///
/// `analyze_param_usage` and the crediting passes it drives used to sweep the
/// whole body once per question -- several times per parameter -- and on a
/// corpus prescan those sweeps were a tenth of all the work.
struct BodySweep<'a> {
    calls: Vec<Node<'a>>,
    assignments: Vec<Node<'a>>,
    updates: Vec<Node<'a>>,
}

impl<'a> BodySweep<'a> {
    fn of(body: &Node<'a>) -> Self {
        use lang_parsing_substrate::query;

        let mut sweep = BodySweep {
            calls: Vec::new(),
            assignments: Vec::new(),
            updates: Vec::new(),
        };
        for node in query::find_descendants(*body, |n| {
            matches!(
                n.kind(),
                "call_expression" | "assignment_expression" | "update_expression"
            )
        }) {
            match node.kind() {
                "call_expression" => sweep.calls.push(node),
                "assignment_expression" => sweep.assignments.push(node),
                _ => sweep.updates.push(node),
            }
        }
        sweep
    }
}

/// The `(callee, callee parameter index)` pairs a coverage answer is
/// contingent on. Empty means the answer stands on this function's own
/// writes; see `FunctionSummary::modifies_params_pending`.
type WriteObligations = BTreeSet<(String, usize)>;

/// Whether every path that falls out of `stmt` writes through `param`, and
/// what that answer rests on: `None` is not covered, `Some(set)` is covered
/// provided every pair in `set` is itself a MUST-write, and `Some(empty)` is
/// covered outright.
///
/// The exhaustiveness question AST position cannot answer. sqlite's
/// `fts5CsrPoslist` sets `*pn` and `*pa` in each arm of an if/else and again
/// in both arms of a trailing `if (rc == SQLITE_OK) ... else ...`: every
/// write is nested inside a conditional, and yet no returning path leaves the
/// outputs untouched. Judging such a function by position alone reports its
/// callers' variables uninitialised.
///
/// One arm of that function writes `*pa` only by handing `pa` to
/// `sqlite3Fts5ExprPoslist`, which a structural walk cannot see through. That
/// leg returns an obligation rather than a verdict, so the interprocedural
/// half of the answer is deferred instead of guessed.
///
/// Only an if/else with BOTH arms covered counts. A bare `if` without an
/// `else` and a loop that may run zero times are left as partial -- which is
/// the honest reading and the one the fixture depends on: `set_flag`'s
/// `if`/`else if` has no final `else`. A `switch` is partial too UNLESS it
/// carries a `default`, which makes it exhaustive by construction; see
/// `switch_writes_on_all_paths`.
///
/// Early `return`s are not modelled, matching the simplification
/// `is_unconditionally_reached` already makes.
///
/// Depth-capped. An `if`/`else if` chain nests one level per arm, so a
/// machine-generated chain thousands long recurses as deep, and this runs on
/// prescan worker threads whose stacks are far smaller than the main one --
/// raylib overflowed and aborted the whole scan. Past the cap the answer is
/// the conservative one, which is the same thing an uncovered branch returns.
fn writes_on_all_paths(stmt: &Node, source: &str, param: &str) -> Option<WriteObligations> {
    writes_on_all_paths_capped(stmt, source, param, 0)
}

/// Deep enough for any hand-written nesting, far below the stack a prescan
/// worker gets.
const WRITE_COVERAGE_MAX_DEPTH: u32 = 96;

fn writes_on_all_paths_capped(
    stmt: &Node,
    source: &str,
    param: &str,
    depth: u32,
) -> Option<WriteObligations> {
    if depth >= WRITE_COVERAGE_MAX_DEPTH {
        return None;
    }
    let writes_on_all_paths = |stmt: &Node, source: &str, param: &str| {
        writes_on_all_paths_capped(stmt, source, param, depth + 1)
    };
    match stmt.kind() {
        "compound_statement" | "translation_unit" => {
            // One covering statement is enough, so this is a disjunction --
            // and the cheapest covering statement is the one to report, since
            // an obligation a sibling already discharges outright would just
            // make the whole answer wait on a callee for nothing.
            let mut cursor = stmt.walk();
            let children: Vec<Node> = stmt.named_children(&mut cursor).collect();
            let mut best: Option<WriteObligations> = None;
            for child in &children {
                match writes_on_all_paths(child, source, param) {
                    Some(obligations) if obligations.is_empty() => return Some(obligations),
                    Some(obligations)
                        if best.as_ref().is_none_or(|b| obligations.len() < b.len()) =>
                    {
                        best = Some(obligations);
                    }
                    Some(_) => {}
                    None => {}
                }
            }
            best
        }
        "labeled_statement" => stmt
            .named_child(stmt.named_child_count().saturating_sub(1))
            .and_then(|inner| writes_on_all_paths(&inner, source, param)),
        "else_clause" => stmt
            .named_child(0)
            .and_then(|inner| writes_on_all_paths(&inner, source, param)),
        "if_statement" => {
            // Both arms, so this is a conjunction: the answer needs every
            // obligation either arm raised.
            let (Some(consequence), Some(alternative)) = (
                stmt.child_by_field_name("consequence"),
                stmt.child_by_field_name("alternative"),
            ) else {
                return None;
            };
            let mut obligations = writes_on_all_paths(&consequence, source, param)?;
            obligations.extend(writes_on_all_paths(&alternative, source, param)?);
            Some(obligations)
        }
        "expression_statement" => {
            let expr = stmt.named_child(0)?;
            let lvalue = match expr.kind() {
                "assignment_expression" => expr.child_by_field_name("left"),
                "update_expression" => expr.child_by_field_name("argument"),
                _ => None,
            };
            let writes_here = lvalue
                .and_then(|l| deref_write_root(&l, false))
                .is_some_and(|root| root.utf8_text(source.as_bytes()).unwrap_or("") == param);
            // `os_memset(out, 0, n);` is a write on this path with no
            // assignment operator to find. Asked here
            // rather than credited outright so a call under an `if` stays a
            // MAY-write, exactly as an assignment under one does.
            let library_writes_here = library_written_names(&expr, source).contains(param);
            if writes_here || library_writes_here {
                return Some(WriteObligations::new());
            }
            // `*pn = callee(..., pa)` writes through `pn` here and through
            // `pa` only inside the callee, so the same statement can be a
            // direct write for one parameter and a forwarded one for another.
            let (callee, idx) = forwarded_write_obligation(&expr, source, param)?;
            Some(WriteObligations::from([(callee, idx)]))
        }
        "switch_statement" => switch_writes_on_all_paths(stmt, source, param, depth),
        _ => None,
    }
}

/// A `switch` covers every path leaving it when it has a `default` label and
/// every case group writes through `param`.
///
/// The reason a switch was left partial was "whose `default` may be absent",
/// and that reason expires when the default is present: such a switch is
/// exhaustive by construction, so if every arm writes then so does every path
/// out of the statement. curl's `cw_get_writefunc` assigns all four of its
/// output parameters in each of its three arms and every caller was still
/// reported uninitialised.
///
/// A conjunction over the groups, so the obligations are the union — the same
/// shape the `if`/`else` arm has, one level wider.
fn switch_writes_on_all_paths(
    stmt: &Node,
    source: &str,
    param: &str,
    depth: u32,
) -> Option<WriteObligations> {
    let body = stmt.child_by_field_name("body")?;
    let mut cursor = body.walk();
    let cases: Vec<Node> = body
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "case_statement")
        .collect();
    if cases.is_empty() {
        return None;
    }
    // Without a `default`, some value of the controlling expression leaves the
    // switch having executed none of it.
    if !cases
        .iter()
        .any(|c| c.child_by_field_name("value").is_none())
    {
        return None;
    }

    let mut obligations = WriteObligations::new();
    // Walked in reverse because fall-through runs the other way: a group that
    // does not break continues into the next one, and is covered by whatever
    // covers that. `None` here means the group after this one is not covered.
    let mut next_covered: Option<WriteObligations> = None;
    for case in cases.iter().rev() {
        let covered = match case_group_writes(case, source, param, depth) {
            Some(own) => own,
            None if !case_group_breaks(case) => next_covered.clone()?,
            None => return None,
        };
        obligations.extend(covered.iter().cloned());
        next_covered = Some(covered);
    }
    Some(obligations)
}

/// Coverage of one case group's own statements: a disjunction, since one
/// covering statement in the group is enough — the same rule
/// `compound_statement` applies, over children that share their parent with a
/// `value` label rather than sitting in a block of their own.
fn case_group_writes(
    case: &Node,
    source: &str,
    param: &str,
    depth: u32,
) -> Option<WriteObligations> {
    let value_id = case.child_by_field_name("value").map(|v| v.id());
    let mut cursor = case.walk();
    let mut best: Option<WriteObligations> = None;
    for child in case.named_children(&mut cursor) {
        if Some(child.id()) == value_id {
            continue;
        }
        match writes_on_all_paths_capped(&child, source, param, depth + 1) {
            Some(o) if o.is_empty() => return Some(o),
            Some(o) if best.as_ref().is_none_or(|b| o.len() < b.len()) => best = Some(o),
            Some(_) | None => {}
        }
    }
    best
}

/// Whether a case group ends in a statement that leaves the switch, so it does
/// NOT fall into the group below it. A group with no statements of its own —
/// stacked labels, `case A: case B:` — never breaks, which is what makes it
/// inherit the next group's coverage rather than fail for having written
/// nothing.
fn case_group_breaks(case: &Node) -> bool {
    let value_id = case.child_by_field_name("value").map(|v| v.id());
    let mut cursor = case.walk();
    let statements: Vec<Node> = case
        .named_children(&mut cursor)
        .filter(|c| Some(c.id()) != value_id && c.kind() != "comment")
        .collect();
    statements.last().is_some_and(|last| {
        matches!(
            last.kind(),
            "break_statement" | "return_statement" | "goto_statement" | "continue_statement"
        )
    })
}

/// Every name `body` hands to a callee as a whole argument, casts included.
///
/// Asks the same question as `collect_param_passthroughs`, which strips casts
/// the same way, but keyed on the name rather than on a parameter index: this
/// one only has to know whether a name left the function, not where it landed.
///
/// A set for the same reason as `library_written_names`: one walk, however
/// many parameters ask.
fn forwarded_argument_names(body: &Node, source: &str) -> HashSet<String> {
    use lang_parsing_substrate::query;

    let mut names = HashSet::new();
    for call in query::find_descendants_of_kind(*body, "call_expression") {
        let callee = call
            .child_by_field_name("function")
            .and_then(|f| f.utf8_text(source.as_bytes()).ok())
            .unwrap_or("");
        // The same exclusion `forwarded_write_obligation` makes: these two are
        // the free path's business, not an output-parameter write.
        if callee.is_empty() || callee == "free" || callee == "realloc" {
            continue;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            let stripped = init_state::strip_arg_casts(&arg);
            if stripped.kind() == "identifier" {
                if let Ok(name) = stripped.utf8_text(source.as_bytes()) {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

/// The `(callee, parameter index)` a statement hands `param` to, if any --
/// the interprocedural leg of the coverage walk.
///
/// Argument position is counted exactly as `collect_param_passthroughs`
/// counts it, since the index is looked up against the callee's own summary
/// and the two have to agree. The argument must be the parameter itself,
/// casts and parentheses aside -- `&param` and `param->field` hand the
/// callee something else.
///
/// The first forwarding call in source order wins. A statement that forwards
/// `param` to two callees is really a disjunction -- either writing it
/// suffices -- which a flat obligation set cannot express, so taking one is
/// an under-approximation. That direction only leaves an existing false
/// positive standing; the alternative would suppress a real finding.
fn forwarded_write_obligation(expr: &Node, source: &str, param: &str) -> Option<(String, usize)> {
    use lang_parsing_substrate::query;

    for call in query::find_descendants_of_kind(*expr, "call_expression") {
        let Some(func_node) = call.child_by_field_name("function") else {
            continue;
        };
        let callee = func_node.utf8_text(source.as_bytes()).unwrap_or("");
        // Same exclusion `collect_param_passthroughs` makes: these two are
        // the free path's business, not an output-parameter write.
        if callee.is_empty() || callee == "free" || callee == "realloc" {
            continue;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut callee_idx = 0usize;
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            if matches!(arg.kind(), "," | "(" | ")") {
                continue;
            }
            // `Curl_ssl_random(data, (unsigned char *)rnd, sizeof(*rnd))`
            // forwards `rnd` as surely as a bare `rnd` would; matching only a
            // bare identifier is what hid it.
            let stripped = init_state::strip_arg_casts(&arg);
            if stripped.kind() == "identifier"
                && stripped.utf8_text(source.as_bytes()).unwrap_or("") == param
            {
                return Some((callee.to_string(), callee_idx));
            }
            callee_idx += 1;
        }
    }
    None
}

/// Whether a `while`/`for` head is one that cannot be skipped: no condition at
/// all (`for(;;)`), or a non-zero integer literal (`while(1)`).
///
/// Anything needing evaluation is treated as skippable, which is the
/// conservative reading everywhere else in `clean_paths`.
fn loop_always_enters(stmt: &Node, source: &str) -> bool {
    match stmt.child_by_field_name("condition") {
        None => true,
        Some(condition) => {
            // A `while` head is a `parenthesized_expression`; a `for` head is
            // the expression itself.
            let mut inner = condition;
            while inner.kind() == "parenthesized_expression" {
                match inner.named_child(0) {
                    Some(child) => inner = child,
                    None => return false,
                }
            }
            let text = inner.utf8_text(source.as_bytes()).unwrap_or("").trim();
            inner.kind() == "number_literal" && text.parse::<i64>().is_ok_and(|v| v != 0)
        }
    }
}

/// Whether some path through this function reaches a `return` — or the end of
/// a void body — without the parameter having been written or handed to
/// anything that could write it.
///
/// The dual of `writes_on_all_paths`, and deliberately not its negation:
/// that walk answers "is coverage proven?", where a `None` covers both "there
/// is a path with no write" and "this pass cannot tell". Only the first is a
/// reason to withhold a caller's initialisation credit, so this asks for the
/// path directly. See `FunctionSummary::conditional_modifies_params`.
///
/// "Touched" is any mention of the parameter's identifier, not just a write.
/// A statement that merely reads it is still refused as a clean path, because
/// the mention may be a forward: `query(cf, data, kind, pport, phost)` writes
/// through both pointers and looks like nothing but two identifiers here.
/// Erring this way costs detections, never adds reports.
fn may_return_without_writing(body: &Node, source: &str, param: &str) -> bool {
    let (passes, returns) = clean_paths(body, source, param, 0);
    passes || returns
}

/// Same reasoning and the same cap as `writes_on_all_paths`: this walks a
/// prescan worker's stack, and an unbounded `if`/`else if` chain nests one
/// level per arm.
const CLEAN_PATH_MAX_DEPTH: u32 = 96;

/// `(a path leaves this statement untouched, a path returns from inside it
/// untouched)`.
///
/// Past the depth cap both answers are `false`, which claims nothing — the
/// same direction every other unhandled shape takes.
fn clean_paths(stmt: &Node, source: &str, param: &str, depth: u32) -> (bool, bool) {
    use lang_parsing_substrate::query;

    if depth >= CLEAN_PATH_MAX_DEPTH {
        return (false, false);
    }

    // Asked before the untouched-subtree shortcut below, which would otherwise
    // report a bare `return;` as merely passing through.
    if stmt.kind() == "return_statement" {
        return if guard_dominance::mentions_var(stmt, param, source) {
            (false, false)
        } else {
            (false, true)
        };
    }

    let mentions = guard_dominance::mentions_var(stmt, param, source);
    let returns_somewhere =
        || !query::find_descendants_of_kind(*stmt, "return_statement").is_empty();
    if !mentions && !returns_somewhere() {
        // Nothing in here touches the parameter and nothing in here leaves the
        // function, so every path through it is clean and none of them return.
        return (true, false);
    }

    match stmt.kind() {
        "compound_statement" => {
            let mut cursor = stmt.walk();
            let children: Vec<Node> = stmt.named_children(&mut cursor).collect();
            let mut passes = true;
            let mut returns = false;
            for child in &children {
                if child.kind() == "comment" {
                    continue;
                }
                let (child_passes, child_returns) = clean_paths(child, source, param, depth + 1);
                // Only reachable-while-still-clean returns count.
                returns |= child_returns;
                if !child_passes {
                    passes = false;
                    break;
                }
            }
            (passes, returns)
        }
        "labeled_statement" => stmt
            .named_child(stmt.named_child_count().saturating_sub(1))
            .map(|inner| clean_paths(&inner, source, param, depth + 1))
            .unwrap_or((false, false)),
        "else_clause" => stmt
            .named_child(0)
            .map(|inner| clean_paths(&inner, source, param, depth + 1))
            .unwrap_or((true, false)),
        "if_statement" => {
            let Some(condition) = stmt.child_by_field_name("condition") else {
                return (false, false);
            };
            if guard_dominance::mentions_var(&condition, param, source) {
                // `if (NULL == sign_flag) return;` mentions the parameter
                // without writing or forwarding it, and the arm it guards is
                // one no caller that goes on to READ the variable ever takes.
                // Counting that arm's `return` as an unwritten returning path
                // would make every optional-output function conditional on
                // the strength of a branch its callers cannot reach -- the
                // same discount `is_unconditionally_reached_modulo_null_guard`
                // makes for the MUST set.
                let Some(non_null_on_true) = null_guard_on(&condition, source, param) else {
                    return (false, false);
                };
                let reached = if non_null_on_true {
                    stmt.child_by_field_name("consequence")
                        .map(|c| clean_paths(&c, source, param, depth + 1))
                        .unwrap_or((true, false))
                } else {
                    match stmt.child_by_field_name("alternative") {
                        Some(alternative) => clean_paths(&alternative, source, param, depth + 1),
                        None => (true, false),
                    }
                };
                return reached;
            }
            let (then_passes, then_returns) = stmt
                .child_by_field_name("consequence")
                .map(|c| clean_paths(&c, source, param, depth + 1))
                .unwrap_or((true, false));
            // No `else` is an empty, untouched false branch -- which is
            // precisely why a bare `if` around every write leaves the
            // parameter unwritten.
            let (else_passes, else_returns) = match stmt.child_by_field_name("alternative") {
                Some(alternative) => clean_paths(&alternative, source, param, depth + 1),
                None => (true, false),
            };
            (then_passes || else_passes, then_returns || else_returns)
        }
        "while_statement" | "for_statement" => {
            // Zero iterations is a path through the loop, provided nothing
            // evaluated on the way in touches the parameter -- but only if
            // the loop can decline to run at all. `while(1)` and `for(;;)`
            // always enter, so their bodies write on every path that reaches
            // them: curl's `Curl_get_line` sets `*eof` at the top of a
            // `while(1)`, and reading a zero-iteration path into it reports
            // every caller.
            if loop_always_enters(stmt, source) {
                return stmt
                    .child_by_field_name("body")
                    .map(|b| clean_paths(&b, source, param, depth + 1))
                    .unwrap_or((false, false));
            }
            let body = stmt.child_by_field_name("body");
            let mut cursor = stmt.walk();
            let header_touches = stmt
                .named_children(&mut cursor)
                .filter(|c| body.is_none_or(|b| c.id() != b.id()))
                .any(|c| guard_dominance::mentions_var(&c, param, source));
            if header_touches {
                return (false, false);
            }
            let returns = body
                .map(|b| clean_paths(&b, source, param, depth + 1).1)
                .unwrap_or(false);
            (true, returns)
        }
        "do_statement" => {
            // The body runs before the condition is ever evaluated, so there
            // is no zero-iteration path to fall back on.
            if stmt
                .child_by_field_name("condition")
                .is_some_and(|c| guard_dominance::mentions_var(&c, param, source))
            {
                return (false, false);
            }
            stmt.child_by_field_name("body")
                .map(|b| clean_paths(&b, source, param, depth + 1))
                .unwrap_or((false, false))
        }
        "switch_statement" => {
            // Mirrors `switch_writes_on_all_paths` from the other side: a
            // `switch` with no `default` is not exhaustive, so a controlling
            // value matching no case leaves it having executed nothing. With
            // a `default` nothing is claimed -- proving a clean path through
            // one arm would have to reason about fall-through.
            let Some(condition) = stmt.child_by_field_name("condition") else {
                return (false, false);
            };
            if guard_dominance::mentions_var(&condition, param, source) {
                return (false, false);
            }
            let Some(body) = stmt.child_by_field_name("body") else {
                return (true, false);
            };
            let mut cursor = body.walk();
            let has_default = body
                .named_children(&mut cursor)
                .filter(|c| c.kind() == "case_statement")
                .any(|c| c.child_by_field_name("value").is_none());
            if has_default {
                (false, false)
            } else {
                (true, false)
            }
        }
        // Everything else that mentions the parameter -- an assignment, a
        // declaration, a call, a `goto` -- is refused rather than reasoned
        // about.
        _ => (false, false),
    }
}

// ---------------------------------------------------------------------------
// Conditional-write / return-value correlation
// ---------------------------------------------------------------------------

/// A returning path's classification of its return expression's truthiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetClass {
    Zero,
    NonZero,
    Unknown,
}

/// Cap on live path contexts `compute_conditional_write_return_correlation`
/// carries at once -- each top-level `if`/`else` with no terminal return on
/// either arm doubles the count. Bounded, not recursive, so this is a hard
/// ceiling on a linear scan rather than a depth cap.
const RETURN_CORRELATION_MAX_CONTEXTS: usize = 8;

/// One provisional path through the function body: whether the target
/// parameter has been written by this point, and the literal-constant value
/// (if any) currently held by each local variable this walk is tracking for
/// a later `return VAR;`.
#[derive(Debug, Clone)]
struct ReturnCorrelationCtx {
    written: bool,
    locals: HashMap<String, RetClass>,
}

/// Parse an integer literal's text (decimal or `0x` hex, with a trailing
/// `u`/`l` suffix stripped) into truthiness. `None` for anything this
/// doesn't recognize -- float literals, character constants, expressions.
fn parse_int_literal_class(text: &str) -> Option<RetClass> {
    let t = text.trim_end_matches(['u', 'U', 'l', 'L']);
    let value = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        t.parse::<i64>().ok()?
    };
    Some(if value == 0 {
        RetClass::Zero
    } else {
        RetClass::NonZero
    })
}

/// Classify a `return`'s expression: a literal constant, a negated literal
/// constant (`-1`), or a local variable this walk already resolved to a
/// literal along this path. Anything else (a call, a field access, an
/// unresolved variable) is `Unknown` -- the proof that consumes this
/// abstains rather than guess.
fn classify_return_expr(expr: &Node, source: &str, locals: &HashMap<String, RetClass>) -> RetClass {
    match expr.kind() {
        "number_literal" => {
            let text = expr.utf8_text(source.as_bytes()).unwrap_or("");
            parse_int_literal_class(text).unwrap_or(RetClass::Unknown)
        }
        "identifier" => {
            let name = expr.utf8_text(source.as_bytes()).unwrap_or("");
            locals.get(name).copied().unwrap_or(RetClass::Unknown)
        }
        "unary_expression" => {
            let (Some(op), Some(arg)) = (
                expr.child_by_field_name("operator"),
                expr.child_by_field_name("argument"),
            ) else {
                return RetClass::Unknown;
            };
            if op.utf8_text(source.as_bytes()).unwrap_or("") != "-" {
                return RetClass::Unknown;
            }
            match classify_return_expr(&arg, source, locals) {
                RetClass::Zero => RetClass::Zero,
                RetClass::NonZero => RetClass::NonZero,
                RetClass::Unknown => RetClass::Unknown,
            }
        }
        "parenthesized_expression" => expr
            .named_child(0)
            .map(|inner| classify_return_expr(&inner, source, locals))
            .unwrap_or(RetClass::Unknown),
        _ => RetClass::Unknown,
    }
}

/// If `stmt` is exactly `identifier = <literal>;`, the identifier and its
/// classified value. Anything else -- a compound assignment, a non-literal
/// right-hand side, an lvalue that isn't a bare identifier -- is not this
/// shape.
fn try_literal_assignment<'a>(stmt: &Node<'a>, source: &str) -> Option<(String, RetClass)> {
    let inner = if stmt.kind() == "expression_statement" {
        stmt.named_child(0)?
    } else {
        *stmt
    };
    if inner.kind() != "assignment_expression" {
        return None;
    }
    if inner
        .child_by_field_name("operator")
        .map(|o| o.utf8_text(source.as_bytes()).unwrap_or(""))
        != Some("=")
    {
        return None;
    }
    let left = inner.child_by_field_name("left")?;
    if left.kind() != "identifier" {
        return None;
    }
    let name = left.utf8_text(source.as_bytes()).unwrap_or("").to_string();
    let right = inner.child_by_field_name("right")?;
    let class = classify_return_expr(&right, source, &HashMap::new());
    Some((name, class))
}

/// Does `stmt`'s byte range contain one of the already-identified writes to
/// the target parameter? `write_starts` is the position of each write node
/// `credit_modifies_params` found for this parameter across the whole body,
/// so this reuses that detection rather than re-deriving it.
fn statement_writes(stmt: &Node, write_starts: &[usize]) -> bool {
    write_starts
        .iter()
        .any(|&s| s >= stmt.start_byte() && s < stmt.end_byte())
}

/// Invalidate any local this walk is tracking that `stmt` mentions but that
/// wasn't recognized as a clean literal (re)assignment -- conservatively:
/// carrying forward a stale classification past a statement that could have
/// changed it (inside a loop body this walk does not model, say) is exactly
/// the kind of silent overclaim this proof exists to avoid.
fn invalidate_mentioned_locals(stmt: &Node, source: &str, locals: &mut HashMap<String, RetClass>) {
    for (name, class) in locals.iter_mut() {
        if *class != RetClass::Unknown && guard_dominance::mentions_var(stmt, name, source) {
            *class = RetClass::Unknown;
        }
    }
}

/// Apply one statement's effect (write detection, literal-assignment
/// tracking, or conservative invalidation) to a single path context.
fn apply_statement_to_ctx(
    stmt: &Node,
    source: &str,
    write_starts: &[usize],
    ctx: &mut ReturnCorrelationCtx,
) {
    if statement_writes(stmt, write_starts) {
        ctx.written = true;
    }
    if let Some((name, class)) = try_literal_assignment(stmt, source) {
        ctx.locals.insert(name, class);
    } else {
        invalidate_mentioned_locals(stmt, source, &mut ctx.locals);
    }
}

/// The result of walking one `if`/`else` branch's statement list against a
/// single incoming path context.
enum BranchOutcome {
    /// The branch fell through without an unconditional top-level return;
    /// the context carries on to whatever statement follows the `if`.
    FallsThrough(ReturnCorrelationCtx),
    /// The branch's last reachable top-level statement was an unconditional
    /// `return`, whose (written, class) pair was already pushed to `leaves`.
    Terminated,
    /// The branch contains something this narrow walk does not model
    /// (nested `if`, a loop, `switch`, `goto`) -- abandon the whole proof
    /// for this parameter rather than reason past it.
    Abandon,
}

/// A branch's statement list, unwrapped from either braces (`compound_statement`)
/// or a single bare statement (`if (c) return 0;`, or an `else_clause` wrapping
/// one statement).
fn branch_statements<'a>(branch: &Node<'a>) -> Vec<Node<'a>> {
    let inner = if branch.kind() == "else_clause" {
        match branch.named_child(0) {
            Some(c) => c,
            None => return Vec::new(),
        }
    } else {
        *branch
    };
    if inner.kind() == "compound_statement" {
        let mut cursor = inner.walk();
        inner
            .named_children(&mut cursor)
            .filter(|c| c.kind() != "comment")
            .collect()
    } else {
        vec![inner]
    }
}

fn process_branch(
    stmts: &[Node],
    source: &str,
    write_starts: &[usize],
    mut ctx: ReturnCorrelationCtx,
    leaves: &mut Vec<(bool, RetClass)>,
) -> BranchOutcome {
    for stmt in stmts {
        match stmt.kind() {
            "if_statement" | "while_statement" | "for_statement" | "do_statement"
            | "switch_statement" | "goto_statement" => return BranchOutcome::Abandon,
            "return_statement" => {
                let class = stmt
                    .named_child(0)
                    .map(|e| classify_return_expr(&e, source, &ctx.locals))
                    .unwrap_or(RetClass::Unknown);
                leaves.push((ctx.written, class));
                return BranchOutcome::Terminated;
            }
            _ => apply_statement_to_ctx(stmt, source, write_starts, &mut ctx),
        }
    }
    BranchOutcome::FallsThrough(ctx)
}

/// Prove, if possible, whether the write(s) to a conditionally-modified
/// parameter -- located at each position in `write_starts` -- are correlated
/// with this function's own return value on every one of its resolvable
/// returning paths. See `init_state::ReturnCorrelation`.
///
/// Deliberately narrow: only a single level of top-level `if`/`else`
/// branching is modeled (each fork doubles the live context count, capped at
/// `RETURN_CORRELATION_MAX_CONTEXTS`), and a branch containing further
/// control flow this walk doesn't understand abandons the whole proof for
/// this parameter rather than risk crediting a path it didn't actually
/// trace. This is exactly the shape of lua's `lua_getstack`: an early
/// `if (level < 0) return 0;`, then one `if (...) { status = 1; ar->i_ci =
/// ci; } else status = 0;`, then a trailing `return status;`.
fn compute_conditional_write_return_correlation(
    body: &Node,
    source: &str,
    write_starts: &[usize],
) -> Option<init_state::ReturnCorrelation> {
    if write_starts.is_empty() {
        return None;
    }
    let mut cursor = body.walk();
    let top_stmts: Vec<Node> = body
        .named_children(&mut cursor)
        .filter(|c| c.kind() != "comment")
        .collect();

    let mut contexts = vec![ReturnCorrelationCtx {
        written: false,
        locals: HashMap::new(),
    }];
    let mut leaves: Vec<(bool, RetClass)> = Vec::new();

    for stmt in &top_stmts {
        if contexts.is_empty() {
            break;
        }
        match stmt.kind() {
            "if_statement" => {
                let consequence = stmt.child_by_field_name("consequence")?;
                let alternative = stmt.child_by_field_name("alternative");
                let mut next_contexts = Vec::new();
                for ctx in contexts.drain(..) {
                    let then_stmts = branch_statements(&consequence);
                    match process_branch(
                        &then_stmts,
                        source,
                        write_starts,
                        ctx.clone(),
                        &mut leaves,
                    ) {
                        BranchOutcome::FallsThrough(c) => next_contexts.push(c),
                        BranchOutcome::Terminated => {}
                        BranchOutcome::Abandon => return None,
                    }
                    match &alternative {
                        Some(alt) => {
                            let else_stmts = branch_statements(alt);
                            match process_branch(
                                &else_stmts,
                                source,
                                write_starts,
                                ctx,
                                &mut leaves,
                            ) {
                                BranchOutcome::FallsThrough(c) => next_contexts.push(c),
                                BranchOutcome::Terminated => {}
                                BranchOutcome::Abandon => return None,
                            }
                        }
                        None => next_contexts.push(ctx),
                    }
                }
                if next_contexts.len() > RETURN_CORRELATION_MAX_CONTEXTS {
                    return None;
                }
                contexts = next_contexts;
            }
            "return_statement" => {
                for ctx in contexts.drain(..) {
                    let class = stmt
                        .named_child(0)
                        .map(|e| classify_return_expr(&e, source, &ctx.locals))
                        .unwrap_or(RetClass::Unknown);
                    leaves.push((ctx.written, class));
                }
                break;
            }
            "while_statement" | "for_statement" | "do_statement" | "switch_statement"
            | "goto_statement" => {
                for ctx in contexts.iter_mut() {
                    if statement_writes(stmt, write_starts) {
                        ctx.written = true;
                    }
                    invalidate_mentioned_locals(stmt, source, &mut ctx.locals);
                }
            }
            _ => {
                for ctx in contexts.iter_mut() {
                    apply_statement_to_ctx(stmt, source, write_starts, ctx);
                }
            }
        }
    }

    if leaves.is_empty() || leaves.iter().any(|(_, c)| *c == RetClass::Unknown) {
        return None;
    }
    let has_zero = leaves.iter().any(|(_, c)| *c == RetClass::Zero);
    let has_nonzero = leaves.iter().any(|(_, c)| *c == RetClass::NonZero);
    if !has_zero || !has_nonzero {
        return None;
    }
    let zero_written: Vec<bool> = leaves
        .iter()
        .filter(|(_, c)| *c == RetClass::Zero)
        .map(|(w, _)| *w)
        .collect();
    let nonzero_written: Vec<bool> = leaves
        .iter()
        .filter(|(_, c)| *c == RetClass::NonZero)
        .map(|(w, _)| *w)
        .collect();
    if zero_written.iter().all(|w| !*w) && nonzero_written.iter().all(|w| *w) {
        return Some(init_state::ReturnCorrelation::WriteOnTruthy);
    }
    if zero_written.iter().all(|w| *w) && nonzero_written.iter().all(|w| !*w) {
        return Some(init_state::ReturnCorrelation::WriteOnFalsy);
    }
    None
}

/// Parse `all_files` in parallel and fold the per-file results into one
/// project-wide context. `unit_count` is only what the progress reporter is
/// told it is starting on.
///
impl FunctionSummary {
    /// `frees_params` as a call on 1-based `line` of `source` sees it: an
    /// index stays only if some definition that frees it can compile together
    /// with that line. hostap's `preauth.c` calls `eapol_sm_init(ctx)` inside
    /// `#if defined(IEEE8021X_EAPOL)`, and the only body that frees `ctx` is
    /// the header stub in the `#else` of that macro, so for that call nothing
    /// is freed (ADR-0010 D4).
    pub fn frees_at(&self, source: &str, line: usize) -> HashSet<usize> {
        self.reachable_frees(&self.frees_params, source, line)
    }

    /// [`Self::frees_at`] for the MUST-free set.
    pub fn unconditional_frees_at(&self, source: &str, line: usize) -> HashSet<usize> {
        self.reachable_frees(&self.unconditional_frees_params, source, line)
    }

    fn reachable_frees(&self, set: &HashSet<usize>, source: &str, line: usize) -> HashSet<usize> {
        set.iter()
            .copied()
            .filter(|idx| {
                self.free_arms.get(idx).is_none_or(|arms| {
                    arms.iter()
                        .any(|a| crate::analyze::dead_regions::line_compiles_under(source, line, a))
                })
            })
            .collect()
    }
}

/// Fold one definition's summary into the accumulated summary for that
/// function name.
///
/// A project can ship several definitions of one name -- an `#ifdef`ed
/// platform variant, a test stub beside the real thing -- and aurora-lint has
/// no preprocessor, so it scans all of them and this decides what callers
/// are told. "First one inserted wins" is never the answer: which definition
/// a parallel walk reaches first is arbitrary, so it silently picks one at
/// random (fixed at different times for `frees_params`, for
/// `can_return_null`, and for the output-parameter sets).
///
/// Each field is folded in the direction its own meaning demands. A MAY fact
/// unions -- if any definition might do the thing, callers must be prepared
/// for it. A MUST fact intersects -- a guarantee holds only if every
/// definition offers it. Read each field's own comment below.
pub fn merge_summary_variant(existing: &mut FunctionSummary, summary: FunctionSummary) {
    existing.has_env03_taint_source |= summary.has_env03_taint_source;
    existing.returns_tainted |= summary.returns_tainted;
    existing.has_relative_command_write |= summary.has_relative_command_write;
    // Union `can_return_null` across variants: a project that
    // ships multiple definitions of the same function name
    // (e.g. hostap's real `src/eap_peer/eap.c` eap_get_config
    // beside the `tests/fuzzing/*/*-peer.c` stubs that always
    // `return &static_config;`) must classify callers by the
    // safe direction. Without this union the first-scanned
    // variant won: whichever variant's `can_return_null` was
    // set at insertion silently overwrote every later one, so
    // the real function's nullable return was masked by the
    // stub's non-null return and callers dereferenced its
    // result without a check (hostap eap_teap.c:1387 recall
    // regression, an earlier fix #2).
    existing.can_return_null |= summary.can_return_null;
    // Same direction, same reason: if ANY definition linked under this name
    // hands back a fresh block, a caller that drops the result may be
    // leaking it, and only tracking the result can say. This was not merged
    // at all before an earlier fix (aurora-lint) -- first-inserted won -- so
    // hostap's os_malloc was whichever of os_none.c's `return NULL` stub,
    // os_internal.c's `return malloc(size)` and os_unix.c's traced variant
    // the parallel walk reached first.
    existing.returns_allocation |= summary.returns_allocation;
    existing.returns_pointer |= summary.returns_pointer;
    existing.returned_callees.extend(summary.returned_callees);
    // MAY, like `stores_params` and for the same reason: if any definition
    // under this name links its result somewhere, a caller reporting the
    // dropped result as leaked is wrong on that build.
    existing.returned_value_escapes |= summary.returned_value_escapes;
    existing
        .returned_value_passthroughs
        .extend(summary.returned_value_passthroughs);
    existing
        .returns_from_callees
        .extend(summary.returns_from_callees);
    // A guess in one variant that another variant backs with evidence is
    // not a guess for the merged name. Each variant's evidence is read from
    // that variant alone, BEFORE the union, so the fold does not depend on
    // which side is folded into which: reading `existing.frees_params` after
    // the union credited every index `summary` contributed as
    // evidence-backed, whichever variant it came from, and so silently
    // dropped the guess flag on a name only `summary` guessed at. Order
    // independence is the point — the caller may swap the two variants to
    // pick which definition governs the fields this fold does not merge
    // .
    let backed = &(&existing.frees_params - &existing.frees_params_guessed)
        | &(&summary.frees_params - &summary.frees_params_guessed);
    existing.frees_params.extend(summary.frees_params);
    for (idx, guesses) in summary.frees_params_by_name {
        existing
            .frees_params_by_name
            .entry(idx)
            .or_default()
            .extend(guesses);
    }
    // OR, for the same reason the free facts are unioned: if ANY definition
    // under this name hands its parameter to a call nothing can be read
    // past, the merged summary's silence is not evidence of a release that
    // did not happen.
    existing.sole_param_escapes_unnamed_call |= summary.sole_param_escapes_unnamed_call;
    existing.frees_params_guessed =
        &(&existing.frees_params_guessed | &summary.frees_params_guessed) - &backed;
    // Unioned with the free facts it sits beside: if ANY definition linked
    // under this name takes ownership of the argument, a caller that reports
    // the block leaked afterwards is wrong on that build.
    existing.stores_params.extend(summary.stores_params);
    // Unioned although it is a MUST fact, because each definition is its own
    // configuration: a caller linked against a definition that always frees
    // the argument is using freed memory in that build, and ADR-0010 reports a
    // violation any compilable configuration produces. Intersecting instead
    // lost real use-after-frees: hostap's os_none.c defines an empty os_free,
    // which would strip "frees" from os_free for every caller.
    existing
        .unconditional_frees_params
        .extend(summary.unconditional_frees_params);
    // Each definition's arms travel with its free, so a caller can still
    // tell which definitions it can link against.
    for (idx, arms) in summary.free_arms {
        existing.free_arms.entry(idx).or_default().extend(arms);
    }
    // Union, for the same reason `can_return_null` is unioned:
    // if ANY definition linked under this name can return
    // having left the output parameter unwritten, a caller
    // that reads it is reading something possibly
    // uninitialised.
    existing
        .conditional_modifies_params
        .extend(summary.conditional_modifies_params);
    // A PROOF, not a MAY/MUST fact: keep an index's correlation only where
    // every variant that has an opinion agrees. A variant with no entry for
    // an index is silent, not a disagreement -- e.g. one `#ifdef` branch's
    // definition never reaches a return statement the walk could classify --
    // so it does not by itself invalidate another variant's proof. Two
    // variants proving OPPOSITE correlations for the same index, though,
    // means neither can be trusted for a caller who cannot tell which
    // definition it linked against, so that index is permanently poisoned
    // via `conditional_write_return_correlation_conflicted` rather than just
    // deleted (order-independence: see that field's doc comment).
    for (idx, corr) in summary.conditional_write_return_correlation {
        if existing
            .conditional_write_return_correlation_conflicted
            .contains(&idx)
        {
            continue;
        }
        match existing.conditional_write_return_correlation.get(&idx) {
            Some(existing_corr) if *existing_corr != corr => {
                existing.conditional_write_return_correlation.remove(&idx);
                existing
                    .conditional_write_return_correlation_conflicted
                    .insert(idx);
            }
            Some(_) => {}
            None => {
                existing
                    .conditional_write_return_correlation
                    .insert(idx, corr);
            }
        }
    }
    existing
        .conditional_write_return_correlation_conflicted
        .extend(summary.conditional_write_return_correlation_conflicted);
    for idx in &existing.conditional_write_return_correlation_conflicted {
        existing.conditional_write_return_correlation.remove(idx);
    }
    // The three output-parameter sets, each merged in the
    // direction its own meaning demands. Before this they were not merged at all:
    // whichever definition the parallel walk reached first
    // was inserted whole and every later one was dropped, so
    // a project shipping two definitions of a name got an
    // arbitrary pick -- the same silent failure
    // `can_return_null` had.
    //
    // MUST is INTERSECTED, not unioned. It is a guarantee a
    // caller is credited with: `unconditional_modifies_params`
    // is what clears an "uninitialised" state, so it may hold
    // an index only if EVERY definition linked under this name
    // writes it on every path. Unioning it would credit the
    // caller of a conditional writer because some other
    // variant happened to be unconditional -- the overclaim
    // direction that produced the 1065 recall regressions.
    // Intersection keeps MUST a subset of the unioned MAY, and
    // disjoint from `conditional_modifies_params`: an index in
    // every variant's MUST is in no variant's conditional set.
    existing
        .unconditional_modifies_params
        .retain(|idx| summary.unconditional_modifies_params.contains(idx));
    // MAY is unioned: if any definition may write through the
    // parameter, callers cannot be told it is read-only.
    existing.modifies_params.extend(summary.modifies_params);
    // Pending obligations are a CONJUNCTION -- coverage holds
    // only if every pair in the set is itself a MUST-write --
    // so unioning them across variants hardens the question
    // rather than answering it, which is the conservative
    // direction here too.
    for (idx, obligations) in summary.modifies_params_pending {
        let entry = existing.modifies_params_pending.entry(idx).or_default();
        for obligation in obligations {
            if !entry.contains(&obligation) {
                entry.push(obligation);
            }
        }
    }
    existing.closes_params.extend(summary.closes_params);
    existing.clears_params.extend(summary.clears_params);
    for (idx, fields) in summary.frees_param_fields {
        existing
            .frees_param_fields
            .entry(idx)
            .or_default()
            .extend(fields);
    }
    for (idx, callees) in summary.param_passthroughs {
        existing
            .param_passthroughs
            .entry(idx)
            .or_default()
            .extend(callees);
    }
    for (idx, callees) in summary.unconditional_param_passthroughs {
        existing
            .unconditional_param_passthroughs
            .entry(idx)
            .or_default()
            .extend(callees);
    }
    // MAY, same direction as `modifies_params`: if any definition linked
    // under this name reaches an unresolvable indirect call with the
    // parameter, callers cannot be told its write status is known.
    existing
        .forwards_to_indirect_call
        .extend(summary.forwards_to_indirect_call);
}

/// Demote parameters whose every AST-visible write through them is
/// conditional out of the MUST-write set. See
/// `FunctionSummary::unconditional_modifies_params` for why this subtracts
/// from `modifies_params` instead of rebuilding it.
fn credit_modifies_params(
    body: &Node,
    sweep: &BodySweep,
    source: &str,
    params: &[String],
    cast_aliases: &[Vec<String>],
    summary: &mut FunctionSummary,
) {
    // Every write through a parameter this pass can see, as (the node whose
    // position decides conditionality, the parameter-rooted identifier).
    let mut writes: Vec<(Node, Node)> = Vec::new();
    for &node in &sweep.assignments {
        if let Some(root) = node
            .child_by_field_name("left")
            .and_then(|left| deref_write_root(&left, false))
        {
            writes.push((node, root));
        }
    }
    // `(*p)++` and `++*p` write through p just as `*p = *p + 1` does.
    for &node in &sweep.updates {
        if let Some(root) = node
            .child_by_field_name("argument")
            .and_then(|argument| deref_write_root(&argument, false))
        {
            writes.push((node, root));
        }
    }
    // A library call that writes its output argument is a write at its own
    // position, so it belongs in this list as well as in the MAY set --
    // otherwise `if (x) os_memset(out, 0, n);` reaches the "no write this pass
    // could see" arm below and is promoted to a MUST-write for having been
    // invisible. `library_written_roots` already
    // returns the root, so no `deref_write_root` here: a bare `out` handed to
    // the call is the dereference, and asking again would reject it.
    for &call in &sweep.calls {
        for root in library_written_roots(&call, source) {
            writes.push((call, root));
        }
    }

    // param index -> (any write seen, any unconditional write seen)
    let mut seen: HashMap<usize, (bool, bool)> = HashMap::new();
    for (node, root) in &writes {
        let name = root.utf8_text(source.as_bytes()).unwrap_or("");
        // A write through a cast alias (`cast_aliases_of`) is a write
        // through its parameter, conditional or not by its own position.
        let Some(idx) = params
            .iter()
            .position(|p| !p.is_empty() && p == name)
            .or_else(|| {
                cast_aliases
                    .iter()
                    .position(|a| a.iter().any(|x| x == name))
            })
        else {
            continue;
        };
        let entry = seen.entry(idx).or_insert((false, false));
        entry.0 = true;
        // `if (out) *out = v;` is the optional-output-parameter idiom, and
        // it writes on every path a caller who passes a real pointer can
        // take -- which every caller that goes on to READ the variable did.
        // Counting it conditional makes the standard shape
        // `rc = f(&n, ...); if (rc) return; use(n);` report uninitialised,
        // and sqlite's fts3 alone writes its outputs that way dozens of
        // times over.
        entry.1 |= is_unconditionally_reached_modulo_null_guard(node, body, source, name);
    }

    for &idx in &summary.modifies_params {
        match seen.get(&idx) {
            // Writes found, all of them conditional by position -- a
            // MAY-write unless the branches between them are exhaustive.
            Some((true, false)) => match writes_on_all_paths(body, source, &params[idx]) {
                Some(obligations) if obligations.is_empty() => {
                    summary.unconditional_modifies_params.insert(idx);
                }
                // Covered only through a callee. Park the obligation for
                // `propagate_transitive_modifies`, which runs once every
                // file's summary exists.
                Some(obligations) => {
                    summary
                        .modifies_params_pending
                        .insert(idx, obligations.into_iter().collect());
                }
                None => {}
            },
            // Either an unconditional write, or no write this pass could
            // see -- in which case the text scan's finding stands unrefined.
            _ => {
                summary.unconditional_modifies_params.insert(idx);
            }
        }
    }

    // A callee that performs NO direct write through the parameter never
    // entered `modifies_params`, so the loop above never iterated it and the
    // whole forwarded-write mechanism was unreachable for precisely the class
    // it was built for: curl's `my_md5_init(void *ctx) { md5_init(ctx); }`
    // stayed flagged at every call site. That is why the obligation lattice
    // measured -2 across nine corpora while the class it aimed at was still
    // standing.
    //
    // Gated on `forwarded_argument_names` so the coverage walk is asked only
    // about parameters the body actually hands to a callee. Without a gate
    // this runs the walk -- whose `expression_statement` leg searches each
    // statement's subtree -- over every parameter of every function, which is
    // the superlinear shape this file has been bitten by before.
    let forwarded = forwarded_argument_names(body, source);
    let candidates: Vec<usize> = (0..params.len())
        .filter(|idx| !params[*idx].is_empty())
        .filter(|idx| !summary.modifies_params.contains(idx))
        .filter(|idx| forwarded.contains(&params[*idx]))
        .collect();
    for idx in candidates {
        let Some(obligations) = writes_on_all_paths(body, source, &params[idx]) else {
            continue;
        };
        if obligations.is_empty() {
            // The walk proved a direct write on every path that the text
            // detectors could not see.
            summary.modifies_params.insert(idx);
            summary.unconditional_modifies_params.insert(idx);
        } else {
            // Nothing is claimed yet, and nothing may be: an obligation is a
            // QUESTION about a callee, not a MAY-write. Entering the parameter
            // into `modifies_params` here would answer it in the affirmative
            // for every consumer that reads the MAY set -- including
            // `build_read_only_deref_fns`, which subtracts it, so a callee
            // whose forwarding is never discharged would stop suppressing the
            // conservative `&var` fallback and be credited anyway.
            // `propagate_transitive_modifies` inserts into both sets when it
            // discharges, which is the point at which something IS known.
            summary
                .modifies_params_pending
                .insert(idx, obligations.into_iter().collect());
        }
    }

    // Positive evidence of a conditional write, for the parameters where the
    // MUST verdict came out "not proven": the coverage walk failing is not
    // itself a finding, so ask the dual question and record only a proven
    // answer. Pending parameters are skipped -- their coverage rests on a
    // callee `propagate_transitive_modifies` has yet to settle, and a
    // clean-path proof over this body alone would be answering a question
    // that is still open.
    let conditional: Vec<usize> = summary
        .modifies_params
        .iter()
        .filter(|idx| !summary.unconditional_modifies_params.contains(idx))
        .filter(|idx| !summary.modifies_params_pending.contains_key(idx))
        .filter(|idx| params.get(**idx).is_some_and(|p| !p.is_empty()))
        .copied()
        .collect();
    for idx in conditional {
        if may_return_without_writing(body, source, &params[idx]) {
            summary.conditional_modifies_params.insert(idx);
            let write_starts: Vec<usize> = writes
                .iter()
                .filter(|(_, root)| root.utf8_text(source.as_bytes()).unwrap_or("") == params[idx])
                .map(|(node, _)| node.start_byte())
                .collect();
            if let Some(corr) =
                compute_conditional_write_return_correlation(body, source, &write_starts)
            {
                summary
                    .conditional_write_return_correlation
                    .insert(idx, corr);
            }
        }
    }
}

/// Credit `summary.clears_params` for every call in `body` that hands a
/// parameter, as the first argument (the destination), to one of
/// `clearing_names` -- see `collect_clearing_names`. Casts and parentheses
/// on the argument are transparent (`memset((void *) buf, 0, len)`), and a
/// call under a preprocessor branch inside the body counts: mbedtls's
/// zeroize reaches `explicit_bzero` / `memset_s` / `SecureZeroMemory` /
/// `memset_func` through four `#if` arms, every one of which clears
/// .
fn credit_clears_params(
    calls: &[Node],
    source: &str,
    params: &[String],
    clearing_names: &HashSet<String>,
    summary: &mut FunctionSummary,
) {
    for &call in calls {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        if function.kind() != "identifier"
            || !clearing_names.contains(function.utf8_text(source.as_bytes()).unwrap_or(""))
        {
            continue;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let Some(first) = arguments.named_child(0) else {
            continue;
        };
        let target = init_state::strip_arg_casts(&first);
        if target.kind() != "identifier" {
            continue;
        }
        let arg_name = target.utf8_text(source.as_bytes()).unwrap_or("");
        if let Some(idx) = params.iter().position(|p| !p.is_empty() && p == arg_name) {
            summary.clears_params.insert(idx);
        }
    }
}

/// Credit a single call argument as freeing whichever parameter it names
/// (by value via `frees_params`, or through its pointee via
/// `frees_param_pointees` for the `void **` "safe free" shape), the same
/// classification `strip_free_argument` already gives a literal `free()`
/// argument.
fn credit_frees_one_arg(
    call: &Node,
    arg: Node,
    body: &Node,
    source: &str,
    params: &[String],
    summary: &mut FunctionSummary,
) {
    let Some((target, through_pointee)) = strip_free_argument(arg) else {
        return;
    };
    let arg_name = target.utf8_text(source.as_bytes()).unwrap_or("");
    let Some(idx) = params.iter().position(|p| !p.is_empty() && p == arg_name) else {
        return;
    };
    if through_pointee {
        summary.frees_param_pointees.insert(idx);
        return;
    }
    summary.frees_params.insert(idx);
    if is_unconditionally_reached_modulo_null_guard(call, body, source, arg_name) {
        summary.unconditional_frees_params.insert(idx);
    }
}

/// Credit `summary.frees_params`/`frees_param_pointees` (MAY-free) and
/// `summary.unconditional_frees_params` (MUST-free) for every call in the
/// body that releases one of `params`.
///
/// Three ways a call is recognized as freeing its argument, in the same
/// preference order as the sibling `collect_frees_param_fields` (field-level
/// frees) uses, and for the same reason: a wrapper's own summary must
/// reflect what it actually releases, not just literal `free(param)`, or a
/// project-local deallocator that frees through a macro or by a name-shaped
/// helper (`crypto_ec_key_deinit` calling `EVP_PKEY_free`, hostap's
/// `tls_deinit`, ...) reports every caller that hands it an allocation as a
/// leak. `propagate_transitive_frees` then carries this outward through any
/// further wrapper chain, so fixing it here is enough — no separate
/// crediting is needed at each transitive call site.
///
///  1. Literal `free` — exactly one argument, as C requires.
///  2. A function-like macro that frees (not necessarily nulls) one of its
///     own parameter positions (`macro_expand::macro_frees_param_indices`).
///  3. A plain call whose name matches `ast_utils::is_deallocation_call_name`
///     (`destroy_*`/`free_*`/`..._free`/etc.) — a name-heuristic fallback
///     for ordinary C helper functions, where the engine has nothing to
///     say. Every argument is a candidate, as for literal `free`.
fn credit_frees_params(
    calls: &[Node],
    body: &Node,
    source: &str,
    params: &[String],
    function_macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
    summary: &mut FunctionSummary,
) {
    use crate::analyze::macro_expand::macro_frees_param_indices;
    use crate::utility::cert_c::ast_utils;

    for &call in calls {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        let func_name = function.utf8_text(source.as_bytes()).unwrap_or("");
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut cursor = arguments.walk();
        let real: Vec<Node> = arguments.named_children(&mut cursor).collect();

        // A callee that is not a plain name is a function pointer: the body
        // is readable right up to the call and says nothing past it. Record
        // that the sole parameter went in, so a consumer can tell an empty
        // free set that MEANS "releases nothing" from one that means "the
        // release went somewhere unreadable". Recorded for every
        // such call, not only deallocator-shaped ones -- the callee has no
        // name to be shaped like. One parameter only; see the field's doc
        // for why a second one makes it worthless.
        if function.kind() != "identifier" && params.len() == 1 && !params[0].is_empty() {
            let escapes = real.iter().any(|arg| {
                strip_free_argument(*arg)
                    .map(|(t, _)| t.utf8_text(source.as_bytes()).unwrap_or(""))
                    .is_some_and(|n| n == params[0])
            });
            summary.sole_param_escapes_unnamed_call |= escapes;
        }

        if func_name == "free" {
            let [arg] = real.as_slice() else {
                continue;
            };
            credit_frees_one_arg(&call, *arg, body, source, params, summary);
            continue;
        }

        let macro_idxs = macro_frees_param_indices(function_macros, func_name);
        if !macro_idxs.is_empty() {
            for idx in macro_idxs {
                if let Some(&arg) = real.get(idx) {
                    credit_frees_one_arg(&call, arg, body, source, params, summary);
                }
            }
            continue;
        }

        if ast_utils::is_deallocation_call_name(func_name) {
            // A name shape is a guess, not evidence: this tier exists
            // precisely because the callee has no body to read. Two limits
            // keep the guess defensible.
            //
            // The callee must be spelled as a plain identifier. In
            // `writer->cwt->do_close(data, writer)` the `_close` belongs to a
            // struct FIELD holding a function pointer; the name says nothing
            // about which function actually runs, so the shape is not even
            // evidence about the right callee.
            if function.kind() != "identifier" {
                continue;
            }
            // Nor may the callee be a function-like macro this file defines.
            // Then there is a body to read: if it frees the argument,
            // `macro_frees_param_indices` above already said so; if the
            // expander could not use it (`##`, variadic) the text is still
            // there, and the name is not evidence about it. mbedtls's
            // `LOCAL_INPUT_FREE(input_external, input)` frees a local copy
            // whose name is pasted from the parameter, and guessing from its
            // `_FREE` made every PSA entry point free its caller's buffers.
            if crate::analyze::check_macros::defines_function_macro(source, func_name) {
                continue;
            }
            // Exactly one argument may name a parameter. The wrappers this
            // tier is for release one object (`EVP_PKEY_free(key)`), and an
            // argument that is not a bare parameter name (`sizeof(*ctx)` in
            // `bin_clear_free(ctx, sizeof(*ctx))`) never resolves anyway. But
            // when SEVERAL arguments name parameters, the name says nothing
            // about which one is released, and crediting them all makes the
            // summary claim the function frees parameters it merely reads --
            // curl's `Curl_cwriter_free(data, writer)` then reports every
            // caller's `data` as freed.
            let mut resolving = real.iter().filter(|&&arg| {
                strip_free_argument(arg)
                    .map(|(t, _)| t.utf8_text(source.as_bytes()).unwrap_or(""))
                    .is_some_and(|n| params.iter().any(|p| !p.is_empty() && p == n))
            });
            let (Some(&arg), None) = (resolving.next(), resolving.next()) else {
                continue;
            };
            // Recorded as a guess against the callee's name, not credited:
            // `resolve_name_shaped_frees` folds it in once it can tell
            // whether anything backs it.
            let Some((target, false)) = strip_free_argument(arg) else {
                continue;
            };
            let arg_name = target.utf8_text(source.as_bytes()).unwrap_or("");
            let Some(idx) = params.iter().position(|p| !p.is_empty() && p == arg_name) else {
                continue;
            };
            let Some(arg_pos) = real.iter().position(|a| a.id() == arg.id()) else {
                continue;
            };
            let unconditional =
                is_unconditionally_reached_modulo_null_guard(&call, body, source, arg_name);
            summary.frees_params_by_name.entry(idx).or_default().push((
                func_name.to_string(),
                arg_pos,
                unconditional,
            ));
        }
    }
}

/// Fold every `frees_params_by_name` guess into `frees_params` now that all
/// summaries exist, recording in `frees_params_guessed` the indices for which
/// the name was the only evidence.
///
/// The guess is promoted unless the callee's own body contradicts it. It was
/// credited before the guesses were held apart, it is what stops a leak
/// report at every caller of a name-shaped wrapper, and a callee with a body
/// the prescan could not see through (`sqlite3_free` releasing via the
/// `xFree` function pointer) has an empty summary that means "unseen", not
/// "frees nothing". What the fold adds is the guess-ness, and the fixpoint
/// that follows clears it wherever a forwarded callee's own free of the
/// parameter is real. `macro_aliases` are resolved the way the fixpoint
/// resolves them.
///
/// The contradiction: a callee whose body was seen to work
/// THROUGH that argument -- freeing its fields (`frees_param_fields`) or
/// writing them (`modifies_params`) -- and not to free the argument itself.
/// curl's `up_free(data)` releases `data->state.up.scheme` and seven
/// siblings; hostap's `free_hw_features(wpa_s)` releases `wpa_s->hw.modes`;
/// hostap's `p2p_free_sd_queries(p2p)` walks a list off `p2p->sd_queries`
/// and then writes `p2p->sd_queries = NULL`. Those bodies are not opaque --
/// the analyzer watched them manage the object's parts -- and they hand the
/// object back intact, so the name is wrong about the parameter and
/// crediting it made every later `data->x` at the caller a use-after-free
/// (310 MEM30-C findings sat on such guesses, 0 labeled TP). A body that
/// neither frees nor writes anything of the argument stays a MAY-free:
/// `sqlite3_free`'s says nothing either way. A callee with a still-unfolded
/// guess of its own on that index is not "fields only" -- the fold is one
/// pass, and order must not decide.
fn resolve_name_shaped_frees(
    summaries: &mut HashMap<String, FunctionSummary>,
    macro_aliases: &HashMap<String, String>,
) {
    let corroborated: HashMap<String, HashSet<usize>> = summaries
        .iter()
        .map(|(n, s)| (n.clone(), &s.frees_params - &s.frees_params_guessed))
        .collect();
    // Every parameter index the callee is known OR still guessed to release.
    // Pending `frees_params_by_name` keys count: this fold is one pass, and a
    // callee whose own free is itself an unresolved guess must not read as
    // "frees nothing" merely because it has not been folded yet.
    let may_free: HashMap<String, HashSet<usize>> = summaries
        .iter()
        .map(|(n, s)| {
            (
                n.clone(),
                s.frees_params
                    .iter()
                    .chain(s.frees_params_by_name.keys())
                    .copied()
                    .collect(),
            )
        })
        .collect();
    let works_through_only: HashMap<String, HashSet<usize>> = summaries
        .iter()
        .map(|(n, s)| {
            let through: HashSet<usize> = s
                .frees_param_fields
                .keys()
                .chain(s.modifies_params.iter())
                .copied()
                .collect();
            let empty = HashSet::new();
            (n.clone(), &through - may_free.get(n).unwrap_or(&empty))
        })
        .collect();
    for summary in summaries.values_mut() {
        let guesses = std::mem::take(&mut summary.frees_params_by_name);
        for (idx, callees) in guesses {
            for (callee_name, arg_pos, unconditional) in callees {
                let callee = edge_target(macro_aliases, &callee_name, |n| {
                    corroborated.contains_key(n)
                });
                let backed = (callee == "free" && arg_pos == 0)
                    || corroborated
                        .get(callee)
                        .is_some_and(|f| f.contains(&arg_pos));
                // The callee's body was read well enough to establish which
                // parameter it releases, and this is not that one. That is not
                // an unsupported guess, it is a CONTRADICTED one: the same
                // analysis that saw the free also saw this argument and did not
                // conclude anything was released through it. hostap's
                // `bin_clear_free(void *bin, size_t len)` releases param 0, so
                // the `bin_clear_free(bin, prime_len)` inside
                // `debug_print_bignum` -- where `bin` is a local and
                // `prime_len` the only argument naming a parameter, so the
                // one-resolving-argument rule picks it -- must not make
                // `prime_len` a freed parameter of `debug_print_bignum`, and
                // every one of its callers' `prime_len` a double free (34
                // findings, hostap sae.c, 0 labeled TP).
                //
                // Asked against `may_free`, which counts the callee's own
                // STILL-PENDING name guesses as well as its settled frees.
                // `corroborated` alone is empty for exactly the callees this is
                // about: `bin_clear_free`'s own `os_free(bin)` is itself a
                // guess waiting in this same fold, and the fold is one pass, so
                // order must not decide (the same reason `works_through_only`
                // below is asked that way).
                //
                // An EMPTY `may_free` still licenses the guess: it means the
                // body was never read, or releases through a function pointer
                // the prescan cannot follow (`sqlite3_free`'s `xFree`, lua's
                // `(*g->frealloc)`), which is the "unseen, not nothing" case
                // this tier exists for.
                if !backed
                    && may_free
                        .get(callee)
                        .is_some_and(|f| !f.is_empty() && !f.contains(&arg_pos))
                {
                    continue;
                }
                if !backed
                    && works_through_only
                        .get(callee)
                        .is_some_and(|f| f.contains(&arg_pos))
                {
                    continue;
                }
                let newly = summary.frees_params.insert(idx);
                if unconditional {
                    summary.unconditional_frees_params.insert(idx);
                }
                if backed {
                    summary.frees_params_guessed.remove(&idx);
                } else if newly {
                    summary.frees_params_guessed.insert(idx);
                }
            }
        }
    }
}

/// The names this function hands back to its caller, read through
/// parentheses, casts and both arms of a conditional.
///
/// A local the function returns outlives the call, so a store into what it
/// points at is an escape. That single hop is what makes curl's
/// `hash_elem_create` -- `he = malloc(...); he->ptr = p; return he;` -- a
/// storer of its own parameter, and through it `Curl_hash_add2` and
/// `Curl_conn_meta_set`.
fn returned_names(body: &Node, source: &str) -> HashSet<String> {
    use lang_parsing_substrate::query;

    fn collect(expr: &Node, source: &str, names: &mut HashSet<String>) {
        if expr.kind() == "conditional_expression" {
            for field in ["consequence", "alternative"] {
                if let Some(arm) = expr.child_by_field_name(field) {
                    collect(&arm, source, names);
                }
            }
            return;
        }
        if let Some((node, false)) = strip_free_argument(*expr) {
            names.insert(node.utf8_text(source.as_bytes()).unwrap_or("").to_string());
        }
    }

    let mut names = HashSet::new();
    for ret in query::find_descendants(*body, |n| n.kind() == "return_statement") {
        let mut cursor = ret.walk();
        for expr in ret.named_children(&mut cursor) {
            collect(&expr, source, &mut names);
        }
    }
    names
}

/// Whether an assignment's destination reaches storage that outlives this
/// call, which is what separates handing a block away from merely rebinding
/// a local copy of the pointer.
///
/// Three roots qualify, and each is one of an earlier fix's worked examples:
/// another PARAMETER (`*he_anchor = he` in curl's `hash_elem_link`), a
/// FILE-SCOPE variable (`eap_methods = method` in hostap's
/// `eap_peer_method_register`), and a local this function RETURNS
/// (`he->ptr = p` in curl's `hash_elem_create`).
///
/// A local root that is none of those does NOT qualify, which is deliberate
/// even though it means missing the `last->next = method` arm of the hostap
/// idiom: `last` walks an existing list and only reaches file scope by a
/// chain this pass does not follow. That arm needs no credit of its own --
/// the same function's `eap_methods = method` arm already establishes the
/// MAY fact, which is the polarity `stores_params` is built on.
fn destination_outlives_call(
    left: &Node,
    source: &str,
    params: &[String],
    returned: &HashSet<String>,
) -> bool {
    use crate::utility::cert_c::ast_utils::{self, IdentifierBinding};

    fn is_file_scope(node: &Node, name: &str, source: &str) -> bool {
        matches!(
            ast_utils::resolve_identifier_binding(node, name, source),
            Some(IdentifierBinding::Global(_))
        )
    }

    let Some(root) = deref_write_root(left, false) else {
        // No dereference was crossed, so nothing the caller owns was written
        // -- unless the destination IS the long-lived object: a bare
        // `global = p` stores the block for the rest of the program.
        if left.kind() != "identifier" {
            return false;
        }
        let name = left.utf8_text(source.as_bytes()).unwrap_or("");
        return is_file_scope(left, name, source);
    };

    let name = root.utf8_text(source.as_bytes()).unwrap_or("");
    if name.is_empty() {
        return false;
    }
    params.iter().any(|p| !p.is_empty() && p == name)
        || returned.contains(name)
        || is_file_scope(&root, name, source)
}

/// Credit `summary.stores_params` for every assignment in the body that puts
/// a parameter's value into storage outliving the call.
///
/// A MAY fact, like `frees_params` -- see the field's own documentation for
/// why MUST cannot express the register-or-free contract this exists for.
/// The evidence is the callee's own body and nothing else: no name shape
/// participates, because the wrong default here trades a large false-positive
/// win for silently dropped leaks.
fn credit_stores_params(
    sweep: &BodySweep,
    body: &Node,
    source: &str,
    params: &[String],
    summary: &mut FunctionSummary,
) {
    use crate::utility::cert_c::ast_utils;

    if params.iter().all(|p| p.is_empty()) {
        return;
    }

    let mut returned: Option<HashSet<String>> = None;

    for assign in &sweep.assignments {
        // `p += n` adjusts a value rather than storing one.
        if assign
            .child_by_field_name("operator")
            .map(|o| ast_utils::get_node_text(&o, source))
            != Some("=")
        {
            continue;
        }
        let (Some(left), Some(right)) = (
            assign.child_by_field_name("left"),
            assign.child_by_field_name("right"),
        ) else {
            continue;
        };
        // The value stored must BE a parameter, read through the casts and
        // parens these assignments are routinely written with. `*param` is
        // not the parameter's own value and is rejected with it.
        let Some((stored, false)) = strip_free_argument(right) else {
            continue;
        };
        let stored_name = stored.utf8_text(source.as_bytes()).unwrap_or("");
        let Some(idx) = params
            .iter()
            .position(|p| !p.is_empty() && p == stored_name)
        else {
            continue;
        };
        if summary.stores_params.contains(&idx) {
            continue;
        }
        // A store INTO the parameter's own object is not the parameter
        // escaping: hostap's `dl_list_init(list)` writes `list->next = list`,
        // and that pointer dies with the block it points into. Crediting it
        // made every `dl_list_init(&obj->sessions)` in a constructor read as
        // the object reaching a container.
        if deref_write_root(&left, false)
            .is_some_and(|root| root.utf8_text(source.as_bytes()) == Ok(stored_name))
        {
            continue;
        }
        let returned = returned.get_or_insert_with(|| returned_names(body, source));
        if destination_outlives_call(&left, source, params, returned) {
            summary.stores_params.insert(idx);
        }
    }
}

/// The local a call argument or stored value reaches into, if it names one:
/// `obj`, `(void *) obj`, `&obj->list`, `&obj.hdr`, `&obj[0]`. An interior
/// pointer counts because a container holding `&obj->list` holds `obj`.
fn object_root_name<'a>(expr: &Node<'a>, source: &'a str) -> Option<&'a str> {
    let e = init_state::strip_arg_casts(expr);
    let inner = if e.kind() == "pointer_expression"
        && e.child_by_field_name("operator")
            .is_some_and(|o| o.kind() == "&")
    {
        init_state::strip_arg_casts(&e.child_by_field_name("argument")?)
    } else {
        e
    };
    let mut n = inner;
    loop {
        match n.kind() {
            "identifier" => return n.utf8_text(source.as_bytes()).ok(),
            "field_expression" | "subscript_expression" => {
                n = init_state::strip_arg_casts(&n.child_by_field_name("argument")?);
            }
            _ => return None,
        }
    }
}

/// Credit `summary.returned_value_escapes` when the object this function
/// returns is, somewhere in the body, stored into storage that outlives the
/// call, and record every call the object (or an interior pointer into it)
/// is handed to, for `propagate_returned_value_escapes` to resolve against
/// the callee's `stores_params` once that summary exists.
///
/// `destination_outlives_call` is asked with an EMPTY returned set on
/// purpose: a store INTO the returned object (`obj->self = obj`) is not the
/// object escaping. Only a parameter-rooted or file-scope destination is.
fn credit_returned_value_escapes(
    sweep: &BodySweep,
    body: &Node,
    source: &str,
    params: &[String],
    summary: &mut FunctionSummary,
) {
    use crate::utility::cert_c::ast_utils;

    let returned = returned_names(body, source);
    if returned.is_empty() {
        return;
    }
    let no_returned = HashSet::new();

    for assign in &sweep.assignments {
        if assign
            .child_by_field_name("operator")
            .map(|o| ast_utils::get_node_text(&o, source))
            != Some("=")
        {
            continue;
        }
        let (Some(left), Some(right)) = (
            assign.child_by_field_name("left"),
            assign.child_by_field_name("right"),
        ) else {
            continue;
        };
        if !object_root_name(&right, source).is_some_and(|n| returned.contains(n)) {
            continue;
        }
        if destination_outlives_call(&left, source, params, &no_returned) {
            summary.returned_value_escapes = true;
            break;
        }
    }

    for call in &sweep.calls {
        let Some(callee) = call
            .child_by_field_name("function")
            .filter(|f| f.kind() == "identifier")
        else {
            continue;
        };
        let Some(args) = call.child_by_field_name("arguments") else {
            continue;
        };
        let callee = ast_utils::get_node_text(&callee, source);
        let mut cursor = args.walk();
        for (idx, arg) in args.named_children(&mut cursor).enumerate() {
            if object_root_name(&arg, source).is_some_and(|n| returned.contains(n)) {
                summary
                    .returned_value_passthroughs
                    .insert((callee.to_string(), idx));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_param_usage(
    body: &Node,
    sweep: &BodySweep,
    source: &str,
    body_text: &str,
    params: &[String],
    function_macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
    summary: &mut FunctionSummary,
) {
    // Credited for every definition, including one inside a preprocessor
    // conditional: that arm compiles in some configuration, so its facts are
    // facts about the name (ADR-0010), and definitions from different arms
    // meet in `merge_summary_variant` like any other alternates.
    credit_frees_params(&sweep.calls, body, source, params, function_macros, summary);
    credit_stores_params(sweep, body, source, params, summary);
    credit_returned_value_escapes(sweep, body, source, params, summary);

    // One walk for the whole body, not one per parameter.
    let library_written = library_written_names_in(&sweep.calls, source);
    let cast_aliases: Vec<Vec<String>> = params
        .iter()
        .map(|p| {
            if p.is_empty() {
                Vec::new()
            } else {
                cast_aliases_of(body, source, p)
            }
        })
        .collect();

    for (idx, param_name) in params.iter().enumerate() {
        if param_name.is_empty() {
            continue;
        }

        // Check if parameter is closed as a file/descriptor/handle resource
        // (FIO42-C) BEFORE it is ever reassigned. A plain "closer(param)"
        // text scan can't tell Juliet's goodB2GSink shape (close old handle,
        // *then* reassign) apart from its badSink twin (reassign to a new
        // handle, then close *that*, leaking the original) — both bodies
        // contain the literal substring `fclose(data)`. Only the "closes
        // first" ordering is a real, provable close of the value the caller
        // handed in.
        if closes_param_before_reassignment(sweep, source, param_name) {
            summary.closes_params.insert(idx);
        }

        // Check if parameter is null-checked.
        // Handles all spacings and both NULL/0/nullptr literals since C
        // allows any of these to denote the null pointer.
        //
        // Also recognizes alias null-checks: `TYPE *alias = param;` followed
        // by a null check on `alias` logically null-checks `param` too.
        // Common in libcurl/sqlite wrappers that cast-copy the param first.
        // A cast alias's guard guards the parameter too (`alias_null_checks`).
        let (alias_checked, alias_checked_before_deref) =
            alias_null_checks(body, source, body_text, param_name, &cast_aliases[idx]);
        if body_matches_null_check(body_text, param_name)
            || body_matches_alias_null_check(body_text, param_name)
            || alias_checked
        {
            summary.checks_null_params.insert(idx);
            // ... and, separately, whether that check happens before the
            // first dereference. Same predicates, run against the body text
            // truncated at the first deref, so no spelling drifts between the
            // two answers.
            let before_deref = match first_deref_offset(body_text, param_name) {
                Some(offset) => &body_text[..offset],
                None => body_text,
            };
            if body_matches_null_check(before_deref, param_name)
                || body_matches_alias_null_check(before_deref, param_name)
                || alias_checked_before_deref
            {
                summary.checks_null_params_before_deref.insert(idx);
            }
        }

        // Check if parameter is written through (dereferenced on left side of assignment).
        // Unlike the dereferences_params check below (a deliberate read-or-write
        // superset), `param->field`/`param[i]` alone is NOT enough here -- that
        // matches a plain READ too (e.g. `printIntLine(data->intOne)`), which
        // would wrongly claim the callee initializes/writes the param. Require
        // an actual assignment operator after the arrow/subscript on the same
        // line, mirroring ARR00-C's own write-vs-read line scan.
        if body_has_deref_write(body_text, param_name)
            || line_has_arrow_or_subscript_write(body_text, param_name)
            || is_fd_set_macro_write(&sweep.calls, source, param_name)
            // `os_memset(elems, 0, sizeof(*elems))` writes the output with no
            // assignment operator anywhere.
            || library_written.contains(param_name)
            // A write through a local cast from the parameter writes the
            // caller's object (see `cast_aliases_of`).
            || cast_aliases[idx].iter().any(|alias| {
                alias_written_through(sweep, source, alias) || library_written.contains(alias)
            })
        {
            summary.modifies_params.insert(idx);
        }

        // Check if parameter is dereferenced in any way (read or write)
        let arrow = format!("{}->", param_name);
        if body_text.contains(&format!("*{}", param_name))
            || has_genuine_arrow_read(body_text, param_name)
            || body_text.contains(&format!("{}[", param_name))
            // Cast-then-deref pattern: `*(type *)param` or
            // `((type *)param)->field`/`[i]` -- a genuine dereference of a
            // cast, not merely a cast used as a value (see `cast_then_deref`).
            || cast_then_deref(body_text, param_name)
            || cast_aliases[idx]
                .iter()
                .any(|alias| !alias_derefs(body, source, alias).is_empty())
        {
            summary.dereferences_params.insert(idx);
            summary.uses_params.insert(idx);
        } else if body_text.contains(&arrow) {
            // Every `param->` here is address-of'd: not a read, but still a
            // use of the pointer (see `uses_params`).
            summary.uses_params.insert(idx);
        }
    }

    // Must run after the loop above: it refines `modifies_params` rather
    // than deriving its own write set.
    credit_modifies_params(body, sweep, source, params, &cast_aliases, summary);

    // Detect param pass-through: when a parameter is forwarded to a callee
    collect_param_passthroughs(body, body, source, params, summary);

    // Detect param forwards into an indirect (function-pointer/field) call
    // this build can never resolve to a specific function.
    collect_param_forwards_to_indirect_call(body, source, params, summary);

    // Detect direct field frees off a parameter: free(param->field) or
    // free((*param)->field) (the double-pointer-deref idiom used by
    // `void destroy(T **param)` style destructors).
    collect_frees_param_fields(&sweep.calls, source, params, function_macros, summary);
}

/// POSIX fd_set macros (`FD_ZERO`, `FD_SET`, `FD_CLR`) write through their
/// `fd_set *` argument -- the sole arg for `FD_ZERO`, the last arg for
/// `FD_SET`/`FD_CLR` -- but they're opaque system macros aurora-lint's
/// macro-expansion engine never sees a definition for, so the arrow/subscript
/// text scan above can't see the write either (hostap's
/// `eloop_sock_table_set_fds(struct eloop_sock_table *table, fd_set *fds)`
/// writes its `fds` param purely through `FD_ZERO(fds)`/`FD_SET(sock, fds)`,
/// leaving `fds` looking never-written to callers passing a malloc'd
/// `fd_set *` bare, e.g. `eloop_sock_table_set_fds(&eloop.readers, rfds)`).
fn is_fd_set_macro_write(calls: &[Node], source: &str, param_name: &str) -> bool {
    use lang_parsing_substrate::query;

    for call in calls {
        let Some(func) = call.child_by_field_name("function") else {
            continue;
        };
        if func.kind() != "identifier" {
            continue;
        }
        if !matches!(
            query::node_text(func, source.as_bytes()),
            "FD_ZERO" | "FD_SET" | "FD_CLR"
        ) {
            continue;
        }
        let Some(args) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut cursor = args.walk();
        let real: Vec<Node> = args.named_children(&mut cursor).collect();
        let Some(last) = real.last() else { continue };
        if last.kind() == "identifier" && query::node_text(*last, source.as_bytes()) == param_name {
            return true;
        }
    }
    false
}

/// True if `body` calls `fclose`/`close`/`CloseHandle` with `param_name` as
/// its sole argument at a source position strictly before the first plain
/// reassignment `param_name = ...`. If `param_name` is never reassigned, any
/// closing call anywhere in the body counts. Order-sensitive by design (see
/// call site in `analyze_param_usage`): a body that reassigns before closing
/// only ever closes the *new* value, never the one the caller passed in, so
/// that shape must NOT be credited.
fn closes_param_before_reassignment(sweep: &BodySweep, source: &str, param_name: &str) -> bool {
    use lang_parsing_substrate::query;

    let first_reassign = sweep
        .assignments
        .iter()
        .filter(|n| {
            n.child_by_field_name("left")
                .map(|l| {
                    l.kind() == "identifier" && query::node_text(l, source.as_bytes()) == param_name
                })
                .unwrap_or(false)
        })
        .map(|n| n.start_byte())
        .min();

    let first_close = sweep
        .calls
        .iter()
        .filter(|call| {
            call.child_by_field_name("function")
                .map(|f| {
                    matches!(
                        query::node_text(f, source.as_bytes()),
                        "fclose" | "close" | "CloseHandle"
                    )
                })
                .unwrap_or(false)
        })
        .filter(|call| {
            call.child_by_field_name("arguments")
                .map(|args| {
                    let real: Vec<_> = (0..args.child_count())
                        .filter_map(|i| args.child(i))
                        .filter(|a| a.is_named())
                        .collect();
                    real.len() == 1
                        && real[0].kind() == "identifier"
                        && query::node_text(real[0], source.as_bytes()) == param_name
                })
                .unwrap_or(false)
        })
        .map(|n| n.start_byte())
        .min();

    match (first_close, first_reassign) {
        (Some(close), Some(reassign)) => close < reassign,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// Scan for `free(...)`-shaped calls whose argument is a field access rooted
/// in one of `params` (via `points_to::lvalue_of`, which unwraps
/// `*`/parens/casts), recording the arrow-joined field chain (e.g. `"will"`
/// or `"will->topic"`) against that parameter's index. AST-based (unlike the
/// sibling `free(param)` text scan above) because the chain must be
/// extracted precisely, not just detected.
///
/// Three ways a call is recognized as freeing its argument, in preference
/// order:
///  1. Literal `free` — every argument is a candidate.
///  2. A function-like macro matching the "safe free" idiom (frees AND nulls
///     its parameter — `macro_expand::macro_nulls_param_indices`), e.g.
///     mosquitto's `#define mosquitto_FREE(A) do{ mosquitto_free(A); (A) =
///     NULL; }while(0)`. This is genuine engine-based detection (the macro
///     body is expanded and inspected), independent of the macro's name —
///     "engine, not allowlist", matching MEM30-C's existing use of the same
///     API. Only the argument position(s) the engine identifies are
///     credited.
///  3. A plain call whose name matches `ast_utils::is_deallocation_call_name`
///     (destroy_*/free_*/..._free/etc.) — a name-heuristic fallback for
///     ordinary C helper functions (not macros) and free-shaped macros that
///     don't null their argument, where the engine has nothing to say.
///     Every argument is a candidate, as for literal `free`.
///
/// aurora-lint has no preprocessor, so for (2)/(3) the macro/helper call itself is
/// the only AST evidence available that a free happened inside it (an earlier fix:
/// MEM31-C ownership model).
fn collect_frees_param_fields(
    calls: &[Node],
    source: &str,
    params: &[String],
    function_macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
    summary: &mut FunctionSummary,
) {
    use crate::analyze::macro_expand::macro_nulls_param_indices;
    use crate::analyze::points_to::LValue;
    use crate::utility::cert_c::ast_utils;

    // Flatten a field-access chain into (root variable, arrow-joined field
    // path), e.g. `m->will->topic` -> ("m", "will->topic").
    fn flatten(lv: &LValue) -> (String, Vec<String>) {
        match lv {
            LValue::Var(name) => (name.clone(), Vec::new()),
            LValue::Field(base, field) => {
                let (root, mut fields) = flatten(base);
                fields.push(field.clone());
                (root, fields)
            }
        }
    }

    // Real (non-punctuation) arguments in call order, matching how macro/
    // function parameter indices are counted.
    fn real_args<'a>(arguments: &Node<'a>) -> Vec<Node<'a>> {
        (0..arguments.child_count())
            .filter_map(|i| arguments.child(i))
            .filter(|a| !matches!(a.kind(), "," | "(" | ")"))
            .collect()
    }

    let credit_field = |summary: &mut FunctionSummary, arg: &Node| {
        let Some(lv) = crate::analyze::points_to::lvalue_of(arg, source) else {
            return;
        };
        let (root_name, fields) = flatten(&lv);
        if fields.is_empty() {
            return;
        }
        let Some(idx) = params.iter().position(|p| p == &root_name) else {
            return;
        };
        summary
            .frees_param_fields
            .entry(idx)
            .or_default()
            .insert(fields.join("->"));
    };

    for &call in calls {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        let func_name = function.utf8_text(source.as_bytes()).unwrap_or("");
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let args = real_args(&arguments);

        if func_name == "free" {
            for arg in &args {
                credit_field(summary, arg);
            }
            continue;
        }

        let null_idxs = macro_nulls_param_indices(function_macros, func_name);
        if !null_idxs.is_empty() {
            for idx in null_idxs {
                if let Some(arg) = args.get(idx) {
                    credit_field(summary, arg);
                }
            }
            continue;
        }

        if ast_utils::is_deallocation_call_name(func_name) {
            for arg in &args {
                credit_field(summary, arg);
            }
        }
    }
}

/// Match a null-check expression on `param_name` anywhere in `body_text`.
///
/// Recognizes all spacings of `PARAM op LIT` / `LIT op PARAM` where op is
/// `==`/`!=` and LIT is `NULL`/`0`/`nullptr`, plus the `!PARAM` unary form.
/// Guards against false matches on substrings (e.g., `foo` matching inside
/// `foobar`) via word-boundary checks.
/// Byte offset of the first dereference of `param_name` in `body_text`, or
/// `None` when there is none.
///
/// The patterns are exactly the ones `dereferences_params` is computed from,
/// so the two answers cannot disagree about what a dereference is. `*param`
/// also matches a multiplication (`x * param`), which shortens the
/// before-the-deref prefix and so can only *withhold* a
/// `checks_null_params_before_deref` credit — the conservative direction for
/// a caller using it to suppress.
fn first_deref_offset(body_text: &str, param_name: &str) -> Option<usize> {
    [
        format!("*{}", param_name),
        format!("{}->", param_name),
        format!("{}[", param_name),
        format!("*){}", param_name),
    ]
    .iter()
    .filter_map(|pattern| body_text.find(pattern.as_str()))
    .min()
}

fn body_matches_null_check(body_text: &str, param_name: &str) -> bool {
    // Fast reject: body must at least contain the param name
    if !body_text.contains(param_name) {
        return false;
    }

    // `!{param}` — matches the unary negation null-check idiom
    if contains_word_after_prefix(body_text, "!", param_name) {
        return true;
    }

    for op in ["==", "!="] {
        for lit in ["NULL", "0", "nullptr"] {
            // PARAM op LIT — various spacings
            if contains_word_with_op(body_text, param_name, op, lit) {
                return true;
            }
            // LIT op PARAM — various spacings
            if contains_lit_with_op_word(body_text, lit, op, param_name) {
                return true;
            }
        }
    }

    false
}

/// True if `text` contains `prefix` immediately followed by `word` at a
/// word boundary (prev char not identifier-continuing, next char not
/// identifier-continuing). Used for `!PARAM`.
fn contains_word_after_prefix(text: &str, prefix: &str, word: &str) -> bool {
    let needle = format!("{}{}", prefix, word);
    let bytes = text.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut start = 0;
    while start + needle_bytes.len() <= bytes.len() {
        if let Some(pos) = text[start..].find(&needle) {
            let absolute = start + pos;
            let after = absolute + needle_bytes.len();
            let next_is_ident = bytes
                .get(after)
                .map(|b| is_ident_continue(*b))
                .unwrap_or(false);
            if !next_is_ident {
                return true;
            }
            start = absolute + 1;
        } else {
            break;
        }
    }
    false
}

/// True if `text` contains `word` followed by `op` and `lit`, with word
/// boundaries around the identifiers and arbitrary whitespace between tokens.
/// Uses a hand-rolled scan to avoid pulling in a regex dep for one pattern.
fn contains_word_with_op(text: &str, word: &str, op: &str, lit: &str) -> bool {
    let bytes = text.as_bytes();
    let word_bytes = word.as_bytes();
    let mut start = 0;
    while start + word_bytes.len() <= bytes.len() {
        let pos = match text[start..].find(word) {
            Some(p) => start + p,
            None => break,
        };
        // Word boundary before
        let prev_is_ident = if pos == 0 {
            false
        } else {
            is_ident_continue(bytes[pos - 1])
        };
        let after = pos + word_bytes.len();
        let next_is_ident = bytes
            .get(after)
            .map(|b| is_ident_continue(*b))
            .unwrap_or(false);
        if !prev_is_ident && !next_is_ident {
            // Skip whitespace, then op, then whitespace, then lit (with word boundary after if applicable)
            let mut idx = after;
            while idx < bytes.len() && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
                idx += 1;
            }
            if bytes[idx..].starts_with(op.as_bytes()) {
                idx += op.len();
                while idx < bytes.len() && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
                    idx += 1;
                }
                if bytes[idx..].starts_with(lit.as_bytes()) {
                    let lit_end = idx + lit.len();
                    let next = bytes
                        .get(lit_end)
                        .map(|b| is_ident_continue(*b))
                        .unwrap_or(false);
                    if !next {
                        return true;
                    }
                }
            }
        }
        start = pos + 1;
    }
    false
}

/// Symmetric to `contains_word_with_op` but with `lit` on the left, `word` on the right.
fn contains_lit_with_op_word(text: &str, lit: &str, op: &str, word: &str) -> bool {
    let bytes = text.as_bytes();
    let lit_bytes = lit.as_bytes();
    let mut start = 0;
    while start + lit_bytes.len() <= bytes.len() {
        let pos = match text[start..].find(lit) {
            Some(p) => start + p,
            None => break,
        };
        let prev_is_ident = if pos == 0 {
            false
        } else {
            is_ident_continue(bytes[pos - 1])
        };
        let after = pos + lit_bytes.len();
        let next_is_ident = bytes
            .get(after)
            .map(|b| is_ident_continue(*b))
            .unwrap_or(false);
        if !prev_is_ident && !next_is_ident {
            let mut idx = after;
            while idx < bytes.len() && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
                idx += 1;
            }
            if bytes[idx..].starts_with(op.as_bytes()) {
                idx += op.len();
                while idx < bytes.len() && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
                    idx += 1;
                }
                if bytes[idx..].starts_with(word.as_bytes()) {
                    let word_end = idx + word.len();
                    let next = bytes
                        .get(word_end)
                        .map(|b| is_ident_continue(*b))
                        .unwrap_or(false);
                    if !next {
                        return true;
                    }
                }
            }
        }
        start = pos + 1;
    }
    false
}

fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Detect alias null-check patterns: `TYPE *alias = param;` (or
/// `alias = param;`) followed by a null check on `alias`. Common in
/// libcurl/sqlite wrappers that cast-copy the pointer param first, then
/// null-check the copy (e.g. `struct Curl_easy *data = d; if(!data) ...`).
fn body_matches_alias_null_check(body_text: &str, param_name: &str) -> bool {
    // Scan for `= param_name` occurrences. Each is a candidate assignment.
    // Then find the alias identifier (LHS of that assignment) and check if
    // the body has a null check on the alias.
    let bytes = body_text.as_bytes();
    let mut search_from = 0;
    while search_from < bytes.len() {
        // Find `= param_name` — plain assignment. Must be preceded by non-`=`
        // (to exclude `==`, `!=`) and followed by `;`, `,`, or `)`.
        let needle = format!("= {}", param_name);
        let pos = match body_text[search_from..].find(&needle) {
            Some(p) => search_from + p,
            None => break,
        };
        search_from = pos + 1;

        // Preceded by `=`, `!`, `<`, `>` → not a simple assignment
        if pos > 0 {
            let prev = bytes[pos - 1];
            if prev == b'=' || prev == b'!' || prev == b'<' || prev == b'>' {
                continue;
            }
        }
        let after = pos + needle.len();
        // Must end the identifier: next char not identifier-continuing
        let next = bytes.get(after).copied().unwrap_or(0);
        if is_ident_continue(next) {
            continue;
        }
        // Must be a statement terminator within a few chars
        if next != b';' && next != b',' && next != b')' && !next.is_ascii_whitespace() {
            continue;
        }

        // Scan backward from pos to find the LHS identifier: skip whitespace,
        // then read identifier chars. Stop at `=` / `(` / `,` / `;` / `*`.
        let mut end = pos;
        while end > 0 && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
            end -= 1;
        }
        let lhs_end = end;
        while end > 0 && is_ident_continue(bytes[end - 1]) {
            end -= 1;
        }
        let lhs_start = end;
        if lhs_start >= lhs_end {
            continue;
        }
        let alias = &body_text[lhs_start..lhs_end];
        if alias == param_name {
            continue;
        }
        // Sanity: alias must start with a letter/underscore
        if !matches!(alias.as_bytes()[0], b'a'..=b'z' | b'A'..=b'Z' | b'_') {
            continue;
        }

        // Now check if the body null-checks the alias
        if body_matches_null_check(body_text, alias) {
            return true;
        }
    }
    false
}

/// Detect param pass-through patterns: when a function parameter is forwarded
/// as a whole argument to a callee, casts and parentheses stripped. Used for
/// transitive free propagation. `body` is the enclosing function's own
/// compound_statement, threaded through unchanged across the recursion (distinct from `node`,
/// the recursive traversal cursor) so `is_unconditionally_reached` can be
/// checked against it at each call site.
fn collect_param_passthroughs(
    node: &Node,
    body: &Node,
    source: &str,
    params: &[String],
    summary: &mut FunctionSummary,
) {
    if node.kind() == "call_expression" {
        if let Some(func_node) = node.child_by_field_name("function") {
            let callee_name = func_node
                .utf8_text(source.as_bytes())
                .unwrap_or("")
                .to_string();
            // Skip free/realloc — already handled by frees_params
            if !callee_name.is_empty() && callee_name != "free" && callee_name != "realloc" {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    let unconditional = is_unconditionally_reached(node, body);
                    let mut callee_idx = 0usize;
                    for i in 0..arguments.child_count() {
                        if let Some(arg) = arguments.child(i) {
                            if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                                continue;
                            }
                            // `backend_free((unsigned char *)p)` forwards
                            // `p` as surely as a bare `p` would; matching only
                            // a bare identifier left the transitive-free walk
                            // with no edge to follow.
                            let stripped = init_state::strip_arg_casts(&arg);
                            if stripped.kind() == "identifier" {
                                let arg_text = stripped.utf8_text(source.as_bytes()).unwrap_or("");
                                for (param_idx, param_name) in params.iter().enumerate() {
                                    if !param_name.is_empty() && arg_text == param_name {
                                        summary
                                            .param_passthroughs
                                            .entry(param_idx)
                                            .or_default()
                                            .push((callee_name.clone(), callee_idx));
                                        if unconditional {
                                            summary
                                                .unconditional_param_passthroughs
                                                .entry(param_idx)
                                                .or_default()
                                                .push((callee_name.clone(), callee_idx));
                                        }
                                    }
                                }
                            }
                            callee_idx += 1;
                        }
                    }
                }
            }
        }
        return; // Don't recurse into call_expression children
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            // Don't cross into a nested (swallowed-sibling) function boundary.
            if is_real_nested_function_definition(&child, source) {
                continue;
            }
            collect_param_passthroughs(&child, body, source, params, summary);
        }
    }
}

/// Detect a parameter forwarded, as a bare identifier, into a call through a
/// `field_expression` (`obj->cb(...)`, `obj.cb(...)`) -- the same
/// C-semantics test `prescan::collect_ambiguous_call_targets` uses: the
/// field name has no relationship to any global function of the
/// same name, so this is always a runtime-bound indirect call this build
/// cannot resolve, regardless of surrounding control flow. Deliberately not
/// gated on `is_unconditionally_reached` like `param_passthroughs` is --
/// reaching the indirect call on ANY path is enough to make the parameter's
/// write status unknowable, which is a MAY fact, not a coverage proof.
fn collect_param_forwards_to_indirect_call(
    node: &Node,
    source: &str,
    params: &[String],
    summary: &mut FunctionSummary,
) {
    if node.kind() == "call_expression" {
        if let Some(func_node) = node.child_by_field_name("function") {
            if func_node.kind() == "field_expression" {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    for i in 0..arguments.child_count() {
                        if let Some(arg) = arguments.child(i) {
                            if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                                continue;
                            }
                            let stripped = init_state::strip_arg_casts(&arg);
                            if stripped.kind() == "identifier" {
                                let arg_text = stripped.utf8_text(source.as_bytes()).unwrap_or("");
                                for (param_idx, param_name) in params.iter().enumerate() {
                                    if !param_name.is_empty() && arg_text == param_name {
                                        summary.forwards_to_indirect_call.insert(param_idx);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return; // Don't recurse into call_expression children
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if is_real_nested_function_definition(&child, source) {
                continue;
            }
            collect_param_forwards_to_indirect_call(&child, source, params, summary);
        }
    }
}

/// The name an edge to `callee_name` is looked up under. Through the alias
/// map when that lands on something the scan knows -- `#define mbedtls_free
/// free`, or an alias onto a function with a body -- and otherwise the
/// spelling itself. `#define zfree valkey_free` renames a symbol at link
/// time, but the only body the scan ever saw is `void zfree(void *ptr)`, so
/// resolving the edge to `valkey_free` reached nothing, and valkey's
/// `decrRefCount` -> `zfree(o)` freed nothing in any summary.
/// `free` itself always wins: an alias onto the literal is the mbedtls case
/// and needs no body.
fn edge_target<'a>(
    macro_aliases: &'a HashMap<String, String>,
    callee_name: &'a str,
    known: impl Fn(&str) -> bool,
) -> &'a str {
    use crate::analyze::const_eval::resolve_macro_alias;
    let resolved = resolve_macro_alias(macro_aliases, callee_name);
    if resolved != callee_name && resolved != "free" && !known(resolved) && known(callee_name) {
        callee_name
    } else {
        resolved
    }
}

/// Propagate transitive frees through param pass-through chains.
///
/// If function B passes param 0 to callee C at param 0, and C frees param 0,
/// then B transitively frees param 0. Iterates to fixpoint for deep chains
/// (e.g., A → B → C → D where D calls free).
///
/// `macro_aliases` is the project-wide `#define ALIAS target` map: a
/// pass-through edge names the callee as spelled, and `credit_frees_params`
/// credits only a literal `free`, so a body that frees through
/// `mbedtls_free(p)` (`#define mbedtls_free free`, in a header this file
/// never parsed) is recorded as an edge to a callee that has no summary and
/// never as a free. Resolving the edge's callee through the aliases here --
/// the first point where every file's `#define`s are merged -- lets that
/// edge reach `free` directly, or a real wrapper's summary through a renamed
/// spelling.
pub fn propagate_transitive_frees(
    summaries: &mut HashMap<String, FunctionSummary>,
    macro_aliases: &HashMap<String, String>,
) {
    resolve_name_shaped_frees(summaries, macro_aliases);

    for _pass in 0..10 {
        let mut changed = false;
        let frees_snapshot: HashMap<String, (HashSet<usize>, HashSet<usize>)> = summaries
            .iter()
            .map(|(n, s)| {
                (
                    n.clone(),
                    (s.frees_params.clone(), s.frees_params_guessed.clone()),
                )
            })
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    let callee = edge_target(macro_aliases, callee_name, |n| {
                        frees_snapshot.contains_key(n)
                    });
                    let (callee_frees, callee_guessed) = if callee == "free" && *callee_idx == 0 {
                        (true, false)
                    } else {
                        match frees_snapshot.get(callee) {
                            Some((frees, guessed)) => {
                                (frees.contains(callee_idx), guessed.contains(callee_idx))
                            }
                            None => (false, false),
                        }
                    };
                    if !callee_frees {
                        continue;
                    }
                    if !summary.frees_params.contains(caller_idx) {
                        summary.frees_params.insert(*caller_idx);
                        if callee_guessed {
                            summary.frees_params_guessed.insert(*caller_idx);
                        }
                        changed = true;
                    } else if !callee_guessed && summary.frees_params_guessed.remove(caller_idx) {
                        // Real evidence for an index a name had only guessed.
                        changed = true;
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }

    // Same fixpoint, restricted to the MUST-free (unconditional) subset: a
    // transitive free is only trustworthy for MEM30-C/MEM31-C's "mark as
    // definitely freed" purposes when BOTH the callee's own free and the
    // forwarding call site in each hop of the chain are unconditional
    // — otherwise a helper that only frees its argument on an
    // error path gets treated as always freeing it at every call site.
    for _pass in 0..10 {
        let mut changed = false;
        let unconditional_snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.unconditional_frees_params.clone()))
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.unconditional_param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    let callee = edge_target(macro_aliases, callee_name, |n| {
                        unconditional_snapshot.contains_key(n)
                    });
                    let callee_frees = (callee == "free" && *callee_idx == 0)
                        || unconditional_snapshot
                            .get(callee)
                            .is_some_and(|f| f.contains(callee_idx));
                    if callee_frees && !summary.unconditional_frees_params.contains(caller_idx) {
                        summary.unconditional_frees_params.insert(*caller_idx);
                        changed = true;
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Discharge the coverage obligations `credit_modifies_params` parked in
/// `modifies_params_pending`, promoting a parameter into the MUST-write set
/// once every callee it was forwarded to is known to MUST-write the index it
/// received it at.
///
/// Why this runs here and not where the obligation was raised: the callee's
/// own summary does not exist yet while a file is being analyzed, and for a
/// cross-file callee it cannot -- the same ordering constraint that puts
/// `propagate_transitive_frees` in prescan.
///
/// Iterated to a fixpoint, because promoting one function's output parameter
/// is what discharges its own caller's obligation, and the chains are as deep
/// as the forwarding is (`a -> b -> c`). Purely additive: a pass only ever
/// inserts, so it converges and cannot withdraw a write already proven.
pub fn propagate_transitive_modifies(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.unconditional_modifies_params.clone()))
            .collect();

        // The conditional half of the same fixpoint: a parameter whose
        // coverage rests on a forwarded callee is UNWRITTEN on some path
        // exactly when that callee leaves it unwritten on some path.
        // `classify(number, out)` writes `*out` directly on one arm and hands
        // `out` to `set_flag` on the other, and `set_flag` writes nothing when
        // `number == 0` -- so `classify` can return without writing too, and a
        // structural walk of its body alone can never see that.
        let conditional_snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.conditional_modifies_params.clone()))
            .collect();

        let mut changed = false;
        for summary in summaries.values_mut() {
            let conditional: Vec<usize> = summary
                .modifies_params_pending
                .iter()
                .filter(|(idx, _)| !summary.unconditional_modifies_params.contains(idx))
                .filter(|(idx, _)| !summary.conditional_modifies_params.contains(idx))
                .filter(|(_, obligations)| {
                    obligations.iter().any(|(callee, callee_idx)| {
                        conditional_snapshot
                            .get(callee)
                            .is_some_and(|unwritten| unwritten.contains(callee_idx))
                    })
                })
                .map(|(idx, _)| *idx)
                .collect();
            for idx in conditional {
                summary.conditional_modifies_params.insert(idx);
                changed = true;
            }

            let discharged: Vec<usize> = summary
                .modifies_params_pending
                .iter()
                .filter(|(idx, _)| !summary.unconditional_modifies_params.contains(idx))
                .filter(|(_, obligations)| {
                    obligations.iter().all(|(callee, callee_idx)| {
                        snapshot
                            .get(callee)
                            .is_some_and(|writes| writes.contains(callee_idx))
                    })
                })
                .map(|(idx, _)| *idx)
                .collect();
            for idx in discharged {
                summary.unconditional_modifies_params.insert(idx);
                // Pending parameters never entered the conditional set, but
                // keep the two disjoint by construction rather than by
                // argument -- both are read as a pair.
                summary.conditional_modifies_params.remove(&idx);
                // Keeps `unconditional_modifies_params` a subset of the MAY
                // set for a parameter that reached here through a forward and
                // never had a direct write to put it there.
                summary.modifies_params.insert(idx);
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }
}

/// Carry `forwards_to_indirect_call` through `param_passthroughs` chains to a
/// fixpoint, since the indirection is routinely one or more forwarding hops
/// below the parameter a real caller passed: hostap's
/// `accounting_sta_update_stats` forwards its own `data` param to the named,
/// otherwise-ordinary `hostapd_drv_read_sta_data`, and the actual
/// `hapd->driver->read_sta_data(...)` dispatch lives one hop further in,
/// inside THAT function's body. Uses the full `param_passthroughs` set, not
/// the unconditional subset: unlike a write-coverage proof, "this parameter
/// might reach an unresolvable call" only needs one reachable path, not
/// every path (see EXP33-C piece (b)).
pub fn propagate_forwards_to_indirect_call(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.forwards_to_indirect_call.clone()))
            .collect();

        let mut changed = false;
        for summary in summaries.values_mut() {
            let newly_unknown: Vec<usize> = summary
                .param_passthroughs
                .iter()
                .filter(|(idx, _)| !summary.forwards_to_indirect_call.contains(idx))
                .filter(|(_, targets)| {
                    targets.iter().any(|(callee, callee_idx)| {
                        snapshot
                            .get(callee)
                            .is_some_and(|unknown| unknown.contains(callee_idx))
                    })
                })
                .map(|(idx, _)| *idx)
                .collect();
            for idx in newly_unknown {
                summary.forwards_to_indirect_call.insert(idx);
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }
}

/// Propagate `callsite_param_tainted`/`callsite_param_taint_observed` through
/// param pass-through chains.
///
/// The base aggregation (`prescan::aggregate_callsite_taint_args`) only sees
/// taint at the *direct* call site — it can't tell that a forwarding
/// wrapper's own parameter is externally tainted, since that wrapper's body
/// contains no taint source, just `callee(param)`. If function B is proven
/// to receive tainted (or proven-clean) data at param `p` and B forwards `p`
/// straight through to callee C at param `q`, then C's call site at `q` is
/// tainted (or clean) too. Iterates to fixpoint for deep chains — Juliet's
/// CWE-134 flow variants nest up to 5 files deep (variant 54). Skips
/// header-declared callees: their external callers are unknowable, so
/// nothing here should assert their call sites are conclusively observed.
/// For the same reason a callee whose caller set is open
/// (`FunctionSummary::caller_set_is_closed`) takes only the tainted half:
/// `aggregate_callsite_taint_args` never records a clean observation for it,
/// and a forwarded one must not either.
pub fn propagate_transitive_param_taint(
    summaries: &mut HashMap<String, FunctionSummary>,
    header_declared: &HashSet<String>,
) {
    for _pass in 0..10 {
        let mut changed = false;

        // Snapshot every forwarding edge (is the source param observed/
        // tainted, and which callee/param does it feed) before mutating —
        // the callee being written may be a different map entry than the
        // caller being read, so this can't be done through a single
        // `values_mut()` pass like `propagate_transitive_frees`.
        let edges: Vec<(bool, bool, String, usize)> = summaries
            .values()
            .flat_map(|s| {
                let observed = s.callsite_param_taint_observed.clone();
                let tainted = s.callsite_param_tainted.clone();
                s.param_passthroughs
                    .iter()
                    .flat_map(move |(caller_idx, callees)| {
                        let is_observed = observed.contains(caller_idx);
                        let is_tainted = tainted.contains(caller_idx);
                        callees
                            .iter()
                            .map(move |(callee_name, callee_idx)| {
                                (is_observed, is_tainted, callee_name.clone(), *callee_idx)
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        for (is_observed, is_tainted, callee_name, callee_idx) in edges {
            if !is_observed || header_declared.contains(&callee_name) {
                continue;
            }
            if let Some(callee_summary) = summaries.get_mut(&callee_name) {
                if !is_tainted && !callee_summary.caller_set_is_closed() {
                    continue;
                }
                if callee_summary
                    .callsite_param_taint_observed
                    .insert(callee_idx)
                {
                    changed = true;
                }
                if is_tainted && callee_summary.callsite_param_tainted.insert(callee_idx) {
                    changed = true;
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Propagate transitive stores through param pass-through chains.
///
/// If function B hands param 0 to callee C, and C stores it somewhere
/// outliving the call, then B does too. Without this the idiom an earlier fix
/// exists for is out of reach entirely: curl's `Curl_conn_meta_set` stores
/// its `meta_data` only by forwarding it to `Curl_hash_add2`, and releases it
/// on the failure arm through a FUNCTION-POINTER PARAMETER (`meta_dtor(...)`)
/// that no summary and no name shape can read, so the forwarding edge is the
/// only evidence there is.
///
/// Macro aliases are resolved on the edge for the same reason
/// `propagate_transitive_frees` resolves them: a body that stores through a
/// renamed spelling records an edge to a callee with no summary of its own.
pub fn propagate_transitive_stores(
    summaries: &mut HashMap<String, FunctionSummary>,
    macro_aliases: &HashMap<String, String>,
) {
    for _pass in 0..10 {
        let mut changed = false;
        let stores_snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.stores_params.clone()))
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    let callee = edge_target(macro_aliases, callee_name, |n| {
                        stores_snapshot.contains_key(n)
                    });
                    if stores_snapshot
                        .get(callee)
                        .is_some_and(|s| s.contains(callee_idx))
                        && !summary.stores_params.contains(caller_idx)
                    {
                        summary.stores_params.insert(*caller_idx);
                        changed = true;
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Propagate transitive closes through param pass-through chains.
///
/// If function B passes param 0 to callee C at param 0, and C closes param 0
/// (fclose/close/CloseHandle), then B transitively closes param 0. Mirrors
/// `propagate_transitive_frees` for FIO42-C's resource-close tracking.
pub fn propagate_transitive_closes(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let mut changed = false;
        let closes_snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.closes_params.clone()))
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    if let Some(callee_closes) = closes_snapshot.get(callee_name) {
                        if callee_closes.contains(callee_idx)
                            && !summary.closes_params.contains(caller_idx)
                        {
                            summary.closes_params.insert(*caller_idx);
                            changed = true;
                        }
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Propagate transitive clears through param pass-through chains.
///
/// Mirrors `propagate_transitive_closes` for `clears_params`: a wrapper that
/// forwards its parameter to a clearer clears it too. Each edge's callee is
/// resolved through `macro_aliases` first, and an edge landing on one of
/// `call_roles::MEMORY_CLEARING_FUNCS` at argument 0 counts by itself, so
/// `#define port_memset memset` and a wrapper-of-a-wrapper both reach the
/// clear.
pub fn propagate_transitive_clears(
    summaries: &mut HashMap<String, FunctionSummary>,
    macro_aliases: &HashMap<String, String>,
) {
    use crate::utility::cert_c::call_roles;

    for _pass in 0..10 {
        let mut changed = false;
        let snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.clears_params.clone()))
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    let callee = edge_target(macro_aliases, callee_name, |n| {
                        snapshot.contains_key(n) || call_roles::is_memory_clearing_call(n)
                    });
                    let clears = (*callee_idx == 0 && call_roles::is_memory_clearing_call(callee))
                        || snapshot.get(callee).is_some_and(|c| c.contains(callee_idx));
                    if clears && !summary.clears_params.contains(caller_idx) {
                        summary.clears_params.insert(*caller_idx);
                        changed = true;
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Propagate transitive pointee-frees through param pass-through chains.
///
/// Mirrors `propagate_transitive_frees` but for `frees_param_pointees`: a
/// wrapper that hands its own `void **` parameter to a `safe_free()`-style
/// callee frees that parameter's pointee too. Same shape as the field version,
/// and needed for the same reason — real code layers these helpers.
pub fn propagate_transitive_frees_param_pointees(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let mut changed = false;
        let snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.frees_param_pointees.clone()))
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    let frees_pointee = snapshot
                        .get(callee_name)
                        .is_some_and(|s| s.contains(callee_idx));
                    if frees_pointee && !summary.frees_param_pointees.contains(caller_idx) {
                        summary.frees_param_pointees.insert(*caller_idx);
                        changed = true;
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Propagate transitive field-frees through param pass-through chains.
///
/// Mirrors `propagate_transitive_frees` but for `frees_param_fields`: if
/// function B passes its param 0 to callee C at param 0, and C frees field
/// `name` off that param, then B transitively frees field `name` off its
/// own param 0. Needed because real-world destructors usually delegate to
/// helper cleanup functions rather than calling `free(param->field)`
/// directly — e.g. mosquitto's `mosquitto__destroy(mosq)` calls
/// `message__cleanup_all(mosq)` and `will__clear(mosq)`, which are the ones
/// that actually free `mosq`'s fields (an earlier fix: MEM31-C ownership model).
pub fn propagate_transitive_frees_param_fields(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let mut changed = false;
        let snapshot: HashMap<String, HashMap<usize, HashSet<String>>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.frees_param_fields.clone()))
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    let Some(callee_fields) =
                        snapshot.get(callee_name).and_then(|m| m.get(callee_idx))
                    else {
                        continue;
                    };
                    let entry = summary.frees_param_fields.entry(*caller_idx).or_default();
                    for field in callee_fields {
                        if entry.insert(field.clone()) {
                            changed = true;
                        }
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Walk every `return_statement` under `body` and, when the return
/// expression unwraps to a call, record the callee identifier. Used as
/// the transitive-propagation seed for `returns_tainted`.
fn collect_returns_from_callees(body: &Node, source: &str, out: &mut HashSet<String>) {
    let mut returns = Vec::new();
    collect_return_expressions(body, source, &mut returns);
    for ret in returns {
        let inner = unwrap_to_call_node(ret);
        if inner.kind() == "call_expression" {
            if let Some(func) = inner.child_by_field_name("function") {
                let name = func.utf8_text(source.as_bytes()).unwrap_or("");
                let ident = name
                    .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or(name);
                if !ident.is_empty() {
                    out.insert(ident.to_string());
                }
            }
        }
    }
}

/// Peel `parenthesized_expression` / `cast_expression` wrappers so we can
/// see whether the underlying expression is a `call_expression`.
fn unwrap_to_call_node<'a>(mut node: Node<'a>) -> Node<'a> {
    loop {
        match node.kind() {
            "parenthesized_expression" => {
                if let Some(inner) = node.named_child(0) {
                    node = inner;
                    continue;
                }
                break;
            }
            "cast_expression" => {
                if let Some(value) = node.child_by_field_name("value") {
                    node = value;
                    continue;
                }
                break;
            }
            _ => break,
        }
    }
    node
}

/// Close `returns_allocation` through `returned_callees`: a pointer-returning
/// wrapper that hands back what an allocating callee produced is an
/// allocator to ITS caller. `scard = os_zalloc(sizeof(*scard)); ... return
/// scard;` names no allocator, and before this every os_zalloc-backed
/// constructor was dark to MEM31-C. Bounded like the sibling
/// fixpoints.
pub fn propagate_returns_allocation(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let mut changed = false;
        let snapshot: HashMap<String, bool> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.returns_allocation))
            .collect();
        for summary in summaries.values_mut() {
            if summary.returns_allocation || !summary.returns_pointer {
                continue;
            }
            if summary
                .returned_callees
                .iter()
                .any(|c| snapshot.get(c).copied().unwrap_or(false))
            {
                summary.returns_allocation = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

/// Close `returned_value_escapes` against the summaries that could not be
/// read while the body was: a call the returned object was handed to whose
/// callee `stores_params` covers that argument (`dl_list_add(&ctx->list,
/// &obj->list)`, macro aliases resolved on the edge as `propagate_
/// transitive_stores` does), and a returned callee whose own result escapes
/// (a wrapper returning a linking constructor's object). Run AFTER
/// `propagate_transitive_stores`, which is what makes a forwarding wrapper
/// like hostap's `dl_list_add_tail` a store at all. Monotone; a rerun after
/// `resolve_includes` widens the alias map is harmless.
pub fn propagate_returned_value_escapes(
    summaries: &mut HashMap<String, FunctionSummary>,
    macro_aliases: &HashMap<String, String>,
) {
    for _pass in 0..10 {
        let mut changed = false;
        let stores: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.stores_params.clone()))
            .collect();
        let escapes: HashMap<String, bool> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.returned_value_escapes))
            .collect();
        for summary in summaries.values_mut() {
            if summary.returned_value_escapes {
                continue;
            }
            let through_callee = summary.returned_value_passthroughs.iter().any(|(c, idx)| {
                stores
                    .get(edge_target(macro_aliases, c, |n| stores.contains_key(n)))
                    .is_some_and(|s| s.contains(idx))
            });
            let through_return = summary
                .returned_callees
                .iter()
                .any(|c| escapes.get(c).copied().unwrap_or(false));
            if through_callee || through_return {
                summary.returned_value_escapes = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

/// Propagate `returns_tainted` through the call chain formed by
/// `returns_from_callees`. If `g` returns the result of `f(...)` and
/// `f.returns_tainted`, then `g.returns_tainted` too.
///
/// Bounded at 10 passes (matches `propagate_transitive_frees`) to keep
/// prescan cost predictable; Juliet's deepest wrapper chains are 2-3 hops.
pub fn propagate_return_taint(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let mut changed = false;
        let snapshot: HashMap<String, bool> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.returns_tainted))
            .collect();

        for summary in summaries.values_mut() {
            if summary.returns_tainted {
                continue;
            }
            for callee in &summary.returns_from_callees {
                if let Some(&callee_tainted) = snapshot.get(callee) {
                    if callee_tainted {
                        summary.returns_tainted = true;
                        changed = true;
                        break;
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Compute the return value range for an integer-returning function.
///
/// Collects all `return expr;` statements in the body, evaluates each
/// expression as a constant range, and joins them. Returns `None` if any
/// return expression cannot be evaluated (conservative).
fn compute_return_range(
    body: &Node,
    source: &str,
    macros: &MacroConstantMap,
) -> Option<ValueRange> {
    let mut return_exprs = Vec::new();
    collect_return_expressions(body, source, &mut return_exprs);

    if return_exprs.is_empty() {
        return None;
    }

    let empty_vars = VarRangeMap::new();
    let mut combined: Option<ValueRange> = None;

    for expr_node in &return_exprs {
        // Try to evaluate the return expression as a constant range.
        // Uses empty var_ranges — only resolves literals, macros, sizeof, and
        // arithmetic on those. Parameter-dependent returns yield None.
        let range = const_eval::try_evaluate_range(expr_node, source, macros, &empty_vars)?;
        combined = Some(match combined {
            Some(existing) => {
                ValueRange::new(existing.min.min(range.min), existing.max.max(range.max))
            }
            None => range,
        });
    }

    combined
}

/// True when the body has at least one `return expr;` and every one of them is
/// a compile-time constant in the weak sense of
/// [`const_eval::is_compile_time_constant_expr`] — see
/// [`FunctionSummary::returns_only_compile_time_constants`].
///
/// Only per-file macro names are available here, so the project-wide sets are
/// [`const_eval::ConstantNameSets::none`]; the unresolvable-identifier rule
/// inside the predicate is what carries the cross-header cases.
fn returns_only_compile_time_constants(
    body: &Node,
    source: &str,
    macros: &MacroConstantMap,
) -> bool {
    let mut return_exprs = Vec::new();
    collect_return_expressions(body, source, &mut return_exprs);

    if return_exprs.is_empty() {
        return false;
    }

    return_exprs.iter().all(|expr| {
        const_eval::is_compile_time_constant_expr(
            expr,
            source,
            macros,
            const_eval::ConstantNameSets::none(),
        )
    })
}

/// Recursively collect the expression child of every `return_statement` in `node`.
fn collect_return_expressions<'a>(node: &Node<'a>, source: &str, out: &mut Vec<Node<'a>>) {
    if node.kind() == "return_statement" {
        // The return expression is the first non-keyword child
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "return" && child.kind() != ";" {
                    out.push(child);
                    return;
                }
            }
        }
        // Bare `return;` — no expression (void-style)
        return;
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            // Don't cross into a nested (swallowed-sibling) function boundary.
            if is_real_nested_function_definition(&child, source) {
                continue;
            }
            collect_return_expressions(&child, source, out);
        }
    }
}

/// The declared name of a function definition node, or `None` if it can't
/// be extracted (e.g. a malformed declarator).
pub fn extract_function_name(func_node: &Node, source: &str) -> Option<String> {
    let declarator = func_node.child_by_field_name("declarator")?;
    let name = extract_leaf_identifier(&declarator, source);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn extract_leaf_identifier(node: &Node, source: &str) -> String {
    match node.kind() {
        "identifier" => node.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
        "function_declarator" | "pointer_declarator" | "array_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                extract_leaf_identifier(&inner, source)
            } else {
                String::new()
            }
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        return child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    }
                }
            }
            String::new()
        }
    }
}

/// Infer the null state of a call argument from AST structure alone.
///
/// Used during prescan to collect argument states at each call site without
/// running full dataflow. Returns:
/// - DefinitelyNull for NULL/0/nullptr literals or casts wrapping them
/// - NotNull for string literals, &var, non-zero numeric literals
/// - Unknown for identifiers and complex expressions (conservative)
pub fn infer_arg_null_state(arg: &Node, source: &str) -> NullState {
    match arg.kind() {
        "null" | "nullptr" => NullState::DefinitelyNull,
        "number_literal" => {
            let text = arg.utf8_text(source.as_bytes()).unwrap_or("").trim();
            if text == "0" {
                NullState::DefinitelyNull
            } else {
                NullState::NotNull
            }
        }
        "string_literal" | "concatenated_string" | "char_literal" => NullState::NotNull,
        "unary_expression" => {
            // &var is always non-null
            if let Some(op) = arg.child_by_field_name("operator") {
                if op.utf8_text(source.as_bytes()).unwrap_or("") == "&" {
                    return NullState::NotNull;
                }
            }
            NullState::Unknown
        }
        "pointer_expression" => {
            // tree-sitter-c parses both `&var` and `*ptr` as pointer_expression.
            // The address of anything is always non-null; the pointee of `*ptr`
            // is unknown. Address-of is the common form for call arguments
            // (`&buf[i]`, `&obj.field`, `&var`), so without this arm caller-context
            // never accumulates non-null evidence from address-of call sites.
            if let Some(op) = arg.child_by_field_name("operator") {
                if op.utf8_text(source.as_bytes()).unwrap_or("") == "&" {
                    return NullState::NotNull;
                }
            }
            NullState::Unknown
        }
        "cast_expression" => {
            // (type*)NULL or (type*)0
            if let Some(value) = arg.child_by_field_name("value") {
                let inner = infer_arg_null_state(&value, source);
                if inner == NullState::DefinitelyNull {
                    return NullState::DefinitelyNull;
                }
            }
            NullState::Unknown
        }
        "parenthesized_expression" => {
            // Unwrap (expr)
            if let Some(inner) = arg.child(1) {
                return infer_arg_null_state(&inner, source);
            }
            NullState::Unknown
        }
        "identifier" => {
            let text = arg.utf8_text(source.as_bytes()).unwrap_or("");
            if text == "NULL" {
                NullState::DefinitelyNull
            } else if matches!(text, "stdout" | "stderr" | "stdin") {
                // Standard C streams are guaranteed non-null
                NullState::NotNull
            } else {
                NullState::Unknown
            }
        }
        _ => NullState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_summarize(code: &str) -> HashMap<String, FunctionSummary> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let macros = const_eval::collect_macro_constants(&tree.root_node(), code);
        compute_summaries(
            &tree.root_node(),
            code,
            &macros,
            true,
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
    }

    #[test]
    fn ifdef_variants_in_one_file_merge_rather_than_last_one_winning() {
        // aurora-lint does not preprocess, so both arms of an `#ifdef` are
        // parsed and both produce a summary for the same name. The `#else`
        // stub is textually last, so a plain insert let the do-nothing variant
        // govern every caller -- `fill` looked like it writes nothing at all
        // .
        //
        // Mirrored the way the cross-file test is, so neither arm alone gives
        // this answer: the real arm alone puts index 1 in MUST, the stub arm
        // alone leaves MAY empty. Only the merge yields both.
        let code = r#"
        #ifdef HAVE_FEATURE
        void fill(int flag, int *out) {
            *out = 1;
        }
        #else
        void fill(int flag, int *out) {
            (void)flag;
            (void)out;
        }
        #endif
        "#;
        let summaries = parse_and_summarize(code);
        let fill = summaries.get("fill").expect("fill summary");

        assert!(
            fill.modifies_params.contains(&1),
            "MAY is unioned: the real arm writes through the parameter, and the \
             stub arm being textually last must not erase that -- got {:?}",
            fill.modifies_params
        );
        assert!(
            !fill.unconditional_modifies_params.contains(&1),
            "MUST is intersected: the stub arm offers no guarantee, so neither \
             does the merged summary -- got {:?}",
            fill.unconditional_modifies_params
        );
    }

    #[test]
    fn test_never_returns() {
        let code = r#"
        void die(const char *msg) {
            fprintf(stderr, "%s\n", msg);
            abort();
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("die").unwrap();
        assert!(summary.never_returns);
    }

    #[test]
    fn test_frees_params() {
        let code = r#"
        void cleanup(void *ptr) {
            free(ptr);
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("cleanup").unwrap();
        assert!(summary.frees_params.contains(&0));
    }

    #[test]
    fn test_can_return_null() {
        let code = r#"
        char *find_match(const char *haystack, const char *needle) {
            char *result = strstr(haystack, needle);
            if (!result) {
                return NULL;
            }
            return result;
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("find_match").unwrap();
        assert!(summary.can_return_null);
    }

    #[test]
    fn test_checks_null_params() {
        let code = r#"
        int safe_strlen(const char *s) {
            if (s == NULL) {
                return 0;
            }
            return strlen(s);
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("safe_strlen").unwrap();
        assert!(summary.checks_null_params.contains(&0));
    }

    #[test]
    fn test_modifies_params() {
        let code = r#"
        void init_struct(struct config *cfg) {
            cfg->value = 0;
            cfg->name = "default";
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("init_struct").unwrap();
        assert!(summary.modifies_params.contains(&0));
    }

    #[test]
    fn test_modifies_params_excludes_read_only_arrow_access() {
        // A follow-on regression: a plain READ through param->field
        // or param[i] (no assignment) must NOT count as modifies_params --
        // confirmed as a real Juliet CWE-476 false-negative source when this
        // was wrongly treated as a write (badSink(struct *data) { if (cond)
        // printIntLine(data->intOne); } was credited with initializing data).
        let code = r#"
        void read_only_sink(struct thing *data) {
            if (cond) {
                printIntLine(data->intOne);
            }
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("read_only_sink").unwrap();
        assert!(
            !summary.modifies_params.contains(&0),
            "a read-only data->field access must not be treated as a write"
        );
        assert!(
            summary.dereferences_params.contains(&0),
            "it should still count as a dereference (the read-or-write superset)"
        );
    }

    #[test]
    fn test_modifies_params_still_detects_arrow_write() {
        let code = r#"
        void write_sink(struct thing *data) {
            data->intOne = 5;
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("write_sink").unwrap();
        assert!(summary.modifies_params.contains(&0));
    }

    #[test]
    fn test_modifies_params_still_detects_subscript_write() {
        let code = r#"
        void fill(int *buf) {
            for (int i = 0; i < 10; i++) {
                buf[i] = i;
            }
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("fill").unwrap();
        assert!(summary.modifies_params.contains(&0));
    }

    #[test]
    fn test_modifies_params_detects_walking_pointer_deref_write() {
        // curl's Curl_rand_bytes shape: `*rnd++ = value;` -- a
        // bare deref-write with a post-increment interposed between the
        // identifier and `=`, which a literal `"*rnd ="` substring match
        // misses entirely.
        let code = r#"
        void fill_random(unsigned char *rnd, size_t num) {
            while (num) {
                *rnd++ = 0x42;
                num--;
            }
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("fill_random").unwrap();
        assert!(summary.modifies_params.contains(&0));
    }

    #[test]
    fn test_modifies_params_deref_write_excludes_comparison() {
        let code = r#"
        void check(int *p) {
            if (*p == 5) {
                do_thing();
            }
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("check").unwrap();
        assert!(
            !summary.modifies_params.contains(&0),
            "*p == 5 is a comparison, not a write"
        );
    }

    #[test]
    fn test_returns_allocation() {
        let code = r#"
        char *create_buffer(size_t size) {
            char *buf = malloc(size);
            if (!buf) return NULL;
            memset(buf, 0, size);
            return buf;
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("create_buffer").unwrap();
        assert!(summary.returns_allocation);
        assert!(summary.can_return_null);
    }

    /// hostap's wpa_sm_write_assoc_resp_ies shape: a scratch
    /// buffer is realloc()ed and freed inside, and what comes back is a
    /// cursor into the caller's buffer. The substring scan called this an
    /// allocator and every caller's cursor was then a "leak".
    #[test]
    fn test_returns_cursor_not_allocation_despite_internal_realloc() {
        let code = r#"
        unsigned char *write_ies(unsigned char *pos, size_t len) {
            unsigned char *subelem = NULL;
            unsigned char *nbuf;
            nbuf = os_realloc(subelem, len);
            if (!nbuf) { free(subelem); return NULL; }
            subelem = nbuf;
            memcpy(pos, subelem, len);
            pos += len;
            free(subelem);
            return pos;
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("write_ies").unwrap();
        assert!(
            !summary.returns_allocation,
            "returns a cursor into the caller's buffer, not the scratch block it freed"
        );
    }

    /// The block reaches the return through a copy and a `?:`.
    #[test]
    fn test_returns_allocation_through_copy_and_ternary() {
        let code = r#"
        char *grow(char *p, size_t n, int ok) {
            char *nbuf = realloc(p, n);
            if (!nbuf) return NULL;
            p = nbuf;
            return ok ? p : NULL;
        }
        char *direct(size_t n) {
            return (char *) xmalloc(n);
        }
        "#;
        let summaries = parse_and_summarize(code);
        assert!(summaries.get("grow").unwrap().returns_allocation);
        assert!(summaries.get("direct").unwrap().returns_allocation);
    }

    /// Allocating into an out-parameter and returning the input pointer is
    /// the other common build-then-hand-off shape: the caller owns what
    /// `*out` now points at, not what the function returned.
    #[test]
    fn test_returns_param_while_filling_out_param_is_not_allocation() {
        let code = r#"
        const char *fill(const char *name, char **out) {
            *out = malloc(16);
            return name;
        }
        "#;
        let summaries = parse_and_summarize(code);
        assert!(!summaries.get("fill").unwrap().returns_allocation);
    }

    /// hostap's traced os_malloc: the block comes back offset past a
    /// bookkeeping header. Still the block.
    #[test]
    fn test_returns_allocation_offset_past_header() {
        let code = r#"
        void *os_malloc(size_t size) {
            struct trace *a = malloc(sizeof(*a) + size);
            if (a == NULL) return NULL;
            a->magic = 0x1234;
            return a + 1;
        }
        "#;
        let summaries = parse_and_summarize(code);
        assert!(summaries.get("os_malloc").unwrap().returns_allocation);
    }

    /// Two definitions of one name -- the `#else` stub that returns NULL
    /// and the real one -- must union in the direction that keeps a
    /// caller tracking the result.
    #[test]
    fn test_returns_allocation_unions_across_variants() {
        let code = r#"
        #ifdef CONFIG_NO_OS
        void *os_malloc(size_t size) { return NULL; }
        #else
        void *os_malloc(size_t size) { return malloc(size); }
        #endif
        "#;
        let summaries = parse_and_summarize(code);
        assert!(summaries.get("os_malloc").unwrap().returns_allocation);
        let mut stub = FunctionSummary::default();
        let real = FunctionSummary {
            returns_allocation: true,
            ..Default::default()
        };
        merge_summary_variant(&mut stub, real);
        assert!(stub.returns_allocation);
    }

    /// The fold must give the same answer whichever variant is folded into
    /// which, because the caller swaps them to choose which definition
    /// governs the fields the fold does not merge. The guess
    /// bookkeeping was the one asymmetric field: evidence in one variant
    /// clears the other's guess, and that must not depend on the side it
    /// sits on.
    #[test]
    fn a_free_one_variant_backs_with_evidence_is_no_guess_either_way() {
        let guessed = FunctionSummary {
            frees_params: HashSet::from([1]),
            frees_params_guessed: HashSet::from([1]),
            ..Default::default()
        };
        let backed = FunctionSummary {
            frees_params: HashSet::from([1]),
            ..Default::default()
        };

        let mut folded = guessed.clone();
        merge_summary_variant(&mut folded, backed.clone());
        assert!(folded.frees_params.contains(&1));
        assert!(
            !folded.frees_params_guessed.contains(&1),
            "evidence in the folded-in variant clears the guess"
        );

        let mut swapped = backed;
        merge_summary_variant(&mut swapped, guessed);
        assert!(swapped.frees_params.contains(&1));
        assert!(
            !swapped.frees_params_guessed.contains(&1),
            "and clears it the other way round too"
        );
    }

    /// The mirror case: an index only ONE variant frees, and only as a
    /// name guess, keeps its guess flag. Reading the evidence off the union
    /// counted that index as backed by the variant that never freed it.
    #[test]
    fn a_guess_no_variant_backs_stays_a_guess() {
        let quiet = FunctionSummary::default();
        let guessed = FunctionSummary {
            frees_params: HashSet::from([2]),
            frees_params_guessed: HashSet::from([2]),
            ..Default::default()
        };
        let mut folded = quiet.clone();
        merge_summary_variant(&mut folded, guessed.clone());
        assert!(folded.frees_params_guessed.contains(&2));
        let mut swapped = guessed;
        merge_summary_variant(&mut swapped, quiet);
        assert!(swapped.frees_params_guessed.contains(&2));
    }

    /// curl's curlx_memdup0: the allocation sits in one arm of the
    /// initializer's `?:`.
    #[test]
    fn test_returns_allocation_from_ternary_initializer() {
        let code = r#"
        void *memdup0(const char *src, size_t length) {
            char *buf = (length < SIZE_MAX) ? curlx_malloc(length + 1) : NULL;
            if (!buf) return NULL;
            buf[length] = 0;
            return buf;
        }
        "#;
        let summaries = parse_and_summarize(code);
        assert!(summaries.get("memdup0").unwrap().returns_allocation);
    }

    #[test]
    fn test_return_range_constant() {
        let code = r#"
        int get_five(void) { return 5; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_five").unwrap();
        assert_eq!(summary.return_range, Some(ValueRange::exact(5)));
    }

    #[test]
    fn test_return_range_multiple_paths() {
        let code = r#"
        int get_bounded(int flag) {
            if (flag) return 1;
            return 10;
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_bounded").unwrap();
        assert_eq!(summary.return_range, Some(ValueRange::new(1, 10)));
    }

    #[test]
    fn test_return_range_void() {
        let code = r#"
        void do_nothing(void) { return; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("do_nothing").unwrap();
        assert_eq!(summary.return_range, None);
    }

    #[test]
    fn test_return_range_pointer() {
        let code = r#"
        int *get_ptr(void) { return 0; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_ptr").unwrap();
        assert_eq!(summary.return_range, None);
    }

    #[test]
    fn test_return_range_param_dependent() {
        let code = r#"
        int identity(int x) { return x; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("identity").unwrap();
        // Parameter-dependent return — not evaluable
        assert_eq!(summary.return_range, None);
    }

    #[test]
    fn test_return_range_macro() {
        let code = r#"
        #define MAX_COUNT 100
        int get_max(void) { return MAX_COUNT; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_max").unwrap();
        assert_eq!(summary.return_range, Some(ValueRange::exact(100)));
    }

    #[test]
    fn test_return_range_zero() {
        let code = r#"
        int get_zero(void) { return 0; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_zero").unwrap();
        assert_eq!(summary.return_range, Some(ValueRange::exact(0)));
    }

    #[test]
    fn test_return_range_negative() {
        let code = r#"
        int get_error(void) { return -1; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_error").unwrap();
        assert_eq!(summary.return_range, Some(ValueRange::exact(-1)));
    }

    #[test]
    fn test_ifdef_spanning_brace_does_not_swallow_sibling_summary() {
        // A regression (see the identical fixture and bug
        // description in prescan.rs's
        // test_collect_call_graph_ifdef_spanning_brace_does_not_leak_swallowed_sibling_calls):
        // a brace that opens under `#ifndef SQLITE_OMIT_AUTHORIZATION` and
        // closes under a second, identical guard a few lines later can't be
        // reconciled by tree-sitter-c without a real preprocessor.
        // sqlite3InitOne's function_definition never closes normally
        // ([0..8717] out of an 8718-byte file), nesting sqlite3Init as a
        // descendant at [7870..8717]. Before this fix,
        // `collect_function_summaries` only matched `function_definition` as
        // a direct child of the translation unit (or of a `preproc_*`
        // wrapper), so sqlite3Init -- now nested inside sqlite3InitOne --
        // got zero summary entry: invisible to every interprocedural rule
        // keyed on FunctionSummary (MSC04-C, EXP34-C, MEM30/31-C, null-state,
        // taint) for the rest of the file.
        let code = r#"int sqlite3InitOne(sqlite3 *db, int iDb, char **pzErrMsg, u32 mFlags){
  int rc;
  int i;
#ifndef SQLITE_OMIT_DEPRECATED
  int size;
#endif
  Db *pDb;
  char const *azArg[6];
  int meta[5];
  InitData initData;
  const char *zSchemaTabName;
  int openedTransaction = 0;
  int mask = ((db->mDbFlags & DBFLAG_EncodingFixed) | ~DBFLAG_EncodingFixed);

  assert( (db->mDbFlags & DBFLAG_SchemaKnownOk)==0 );
  assert( iDb>=0 && iDb<db->nDb );
  assert( db->aDb[iDb].pSchema );
  assert( sqlite3_mutex_held(db->mutex) );
  assert( iDb==1 || sqlite3BtreeHoldsMutex(db->aDb[iDb].pBt) );

  db->init.busy = 1;

  /* Construct the in-memory representation schema tables (sqlite_schema or
  ** sqlite_temp_schema) by invoking the parser directly.  The appropriate
  ** table name will be inserted automatically by the parser so we can just
  ** use the abbreviation "x" here.  The parser will also automatically tag
  ** the schema table as read-only. */
  azArg[0] = "table";
  azArg[1] = zSchemaTabName = SCHEMA_TABLE(iDb);
  azArg[2] = azArg[1];
  azArg[3] = "1";
  azArg[4] = "CREATE TABLE x(type text,name text,tbl_name text,"
                            "rootpage int,sql text)";
  azArg[5] = 0;
  initData.db = db;
  initData.iDb = iDb;
  initData.rc = SQLITE_OK;
  initData.pzErrMsg = pzErrMsg;
  initData.mInitFlags = mFlags;
  initData.nInitRow = 0;
  initData.mxPage = 0;
  sqlite3InitCallback(&initData, 5, (char **)azArg, 0);
  db->mDbFlags &= mask;
  if( initData.rc ){
    rc = initData.rc;
    goto error_out;
  }

  /* Create a cursor to hold the database open
  */
  pDb = &db->aDb[iDb];
  if( pDb->pBt==0 ){
    assert( iDb==1 );
    DbSetProperty(db, 1, DB_SchemaLoaded);
    rc = SQLITE_OK;
    goto error_out;
  }

  /* If there is not already a read-only (or read-write) transaction opened
  ** on the b-tree database, open one now. If a transaction is opened, it 
  ** will be closed before this function returns.  */
  sqlite3BtreeEnter(pDb->pBt);
  if( sqlite3BtreeTxnState(pDb->pBt)==SQLITE_TXN_NONE ){
    rc = sqlite3BtreeBeginTrans(pDb->pBt, 0, 0);
    if( rc!=SQLITE_OK ){
      sqlite3SetString(pzErrMsg, db, sqlite3ErrStr(rc));
      goto initone_error_out;
    }
    openedTransaction = 1;
  }

  /* Get the database meta information.
  **
  ** Meta values are as follows:
  **    meta[0]   Schema cookie.  Changes with each schema change.
  **    meta[1]   File format of schema layer.
  **    meta[2]   Size of the page cache.
  **    meta[3]   Largest rootpage (auto/incr_vacuum mode)
  **    meta[4]   Db text encoding. 1:UTF-8 2:UTF-16LE 3:UTF-16BE
  **    meta[5]   User version
  **    meta[6]   Incremental vacuum mode
  **    meta[7]   unused
  **    meta[8]   unused
  **    meta[9]   unused
  **
  ** Note: The #defined SQLITE_UTF* symbols in sqliteInt.h correspond to
  ** the possible values of meta[4].
  */
  for(i=0; i<ArraySize(meta); i++){
    sqlite3BtreeGetMeta(pDb->pBt, i+1, (u32 *)&meta[i]);
  }
  if( (db->flags & SQLITE_ResetDatabase)!=0 ){
    memset(meta, 0, sizeof(meta));
  }
  pDb->pSchema->schema_cookie = meta[BTREE_SCHEMA_VERSION-1];

  /* If opening a non-empty database, check the text encoding. For the
  ** main database, set sqlite3.enc to the encoding of the main database.
  ** For an attached db, it is an error if the encoding is not the same
  ** as sqlite3.enc.
  */
  if( meta[BTREE_TEXT_ENCODING-1] ){  /* text encoding */
    if( iDb==0 && (db->mDbFlags & DBFLAG_EncodingFixed)==0 ){
      u8 encoding;
#ifndef SQLITE_OMIT_UTF16
      /* If opening the main database, set ENC(db). */
      encoding = (u8)meta[BTREE_TEXT_ENCODING-1] & 3;
      if( encoding==0 ) encoding = SQLITE_UTF8;
#else
      encoding = SQLITE_UTF8;
#endif
      sqlite3SetTextEncoding(db, encoding);
    }else{
      /* If opening an attached database, the encoding much match ENC(db) */
      if( (meta[BTREE_TEXT_ENCODING-1] & 3)!=ENC(db) ){
        sqlite3SetString(pzErrMsg, db, "attached databases must use the same"
            " text encoding as main database");
        rc = SQLITE_ERROR;
        goto initone_error_out;
      }
    }
  }
  pDb->pSchema->enc = ENC(db);

  if( pDb->pSchema->cache_size==0 ){
#ifndef SQLITE_OMIT_DEPRECATED
    size = sqlite3AbsInt32(meta[BTREE_DEFAULT_CACHE_SIZE-1]);
    if( size==0 ){ size = SQLITE_DEFAULT_CACHE_SIZE; }
    pDb->pSchema->cache_size = size;
#else
    pDb->pSchema->cache_size = SQLITE_DEFAULT_CACHE_SIZE;
#endif
    sqlite3BtreeSetCacheSize(pDb->pBt, pDb->pSchema->cache_size);
  }

  /*
  ** file_format==1    Version 3.0.0.
  ** file_format==2    Version 3.1.3.  // ALTER TABLE ADD COLUMN
  ** file_format==3    Version 3.1.4.  // ditto but with non-NULL defaults
  ** file_format==4    Version 3.3.0.  // DESC indices.  Boolean constants
  */
  pDb->pSchema->file_format = (u8)meta[BTREE_FILE_FORMAT-1];
  if( pDb->pSchema->file_format==0 ){
    pDb->pSchema->file_format = 1;
  }
  if( pDb->pSchema->file_format>SQLITE_MAX_FILE_FORMAT ){
    sqlite3SetString(pzErrMsg, db, "unsupported file format");
    rc = SQLITE_ERROR;
    goto initone_error_out;
  }

  /* Ticket #2804:  When we open a database in the newer file format,
  ** clear the legacy_file_format pragma flag so that a VACUUM will
  ** not downgrade the database and thus invalidate any descending
  ** indices that the user might have created.
  */
  if( iDb==0 && meta[BTREE_FILE_FORMAT-1]>=4 ){
    db->flags &= ~(u64)SQLITE_LegacyFileFmt;
  }

  /* Read the schema information out of the schema tables
  */
  assert( db->init.busy );
  initData.mxPage = sqlite3BtreeLastPage(pDb->pBt);
  {
    char *zSql;
    zSql = sqlite3MPrintf(db, 
        "SELECT*FROM\"%w\".%s ORDER BY rowid",
        db->aDb[iDb].zDbSName, zSchemaTabName);
#ifndef SQLITE_OMIT_AUTHORIZATION
    {
      sqlite3_xauth xAuth;
      xAuth = db->xAuth;
      db->xAuth = 0;
#endif
      rc = sqlite3_exec(db, zSql, sqlite3InitCallback, &initData, 0);
#ifndef SQLITE_OMIT_AUTHORIZATION
      db->xAuth = xAuth;
    }
#endif
    if( rc==SQLITE_OK ) rc = initData.rc;
    sqlite3DbFree(db, zSql);
#ifndef SQLITE_OMIT_ANALYZE
    if( rc==SQLITE_OK ){
      sqlite3AnalysisLoad(db, iDb);
    }
#endif
  }
  assert( pDb == &(db->aDb[iDb]) );
  if( db->mallocFailed ){
    rc = SQLITE_NOMEM_BKPT;
    sqlite3ResetAllSchemasOfConnection(db);
    pDb = &db->aDb[iDb];
  }else
  if( rc==SQLITE_OK || ((db->flags&SQLITE_NoSchemaError) && rc!=SQLITE_NOMEM)){
    /* Hack: If the SQLITE_NoSchemaError flag is set, then consider
    ** the schema loaded, even if errors (other than OOM) occurred. In
    ** this situation the current sqlite3_prepare() operation will fail,
    ** but the following one will attempt to compile the supplied statement
    ** against whatever subset of the schema was loaded before the error
    ** occurred.
    **
    ** The primary purpose of this is to allow access to the sqlite_schema
    ** table even when its contents have been corrupted.
    */
    DbSetProperty(db, iDb, DB_SchemaLoaded);
    rc = SQLITE_OK;
  }

  /* Jump here for an error that occurs after successfully allocating
  ** curMain and calling sqlite3BtreeEnter(). For an error that occurs
  ** before that point, jump to error_out.
  */
initone_error_out:
  if( openedTransaction ){
    sqlite3BtreeCommit(pDb->pBt);
  }
  sqlite3BtreeLeave(pDb->pBt);

error_out:
  if( rc ){
    if( rc==SQLITE_NOMEM || rc==SQLITE_IOERR_NOMEM ){
      sqlite3OomFault(db);
    }
    sqlite3ResetOneSchema(db, iDb);
  }
  db->init.busy = 0;
  return rc;
}

/*
** Initialize all database files - the main database file, the file
** used to store temporary tables, and any additional database files
** created using ATTACH statements.  Return a success code.  If an
** error occurs, write an error message into *pzErrMsg.
**
** After a database is initialized, the DB_SchemaLoaded bit is set
** bit is set in the flags field of the Db structure. 
*/
int sqlite3Init(sqlite3 *db, char **pzErrMsg){
  int i, rc;
  int commit_internal = !(db->mDbFlags&DBFLAG_SchemaChange);
  
  assert( sqlite3_mutex_held(db->mutex) );
  assert( sqlite3BtreeHoldsMutex(db->aDb[0].pBt) );
  assert( db->init.busy==0 );
  ENC(db) = SCHEMA_ENC(db);
  assert( db->nDb>0 );
  /* Do the main schema first */
  if( !DbHasProperty(db, 0, DB_SchemaLoaded) ){
    rc = sqlite3InitOne(db, 0, pzErrMsg, 0);
    if( rc ) return rc;
  }
  /* All other schemas after the main schema. The "temp" schema must be last */
  for(i=db->nDb-1; i>0; i--){
    assert( i==1 || sqlite3BtreeHoldsMutex(db->aDb[i].pBt) );
    if( !DbHasProperty(db, i, DB_SchemaLoaded) ){
      rc = sqlite3InitOne(db, i, pzErrMsg, 0);
      if( rc ) return rc;
    }
  }
  if( commit_internal ){
    sqlite3CommitInternalChanges(db);
  }
  return SQLITE_OK;
}"#;
        let summaries = parse_and_summarize(code);
        assert!(
            summaries.contains_key("sqlite3Init"),
            "sqlite3Init was swallowed into sqlite3InitOne's corrupted span \
             and got no summary entry of its own: {:?}",
            summaries.keys().collect::<Vec<_>>()
        );
        assert!(summaries.contains_key("sqlite3InitOne"));
    }

    #[test]
    fn test_ifdef_spanning_brace_does_not_contaminate_outer_summary() {
        // Same corruption as above, with a third function appended
        // (`extra_leak_marker`, containing malloc()/abort() -- signals not
        // present anywhere in the real sqlite3InitOne/sqlite3Init source)
        // that also ends up nested inside sqlite3InitOne's corrupted span.
        // Before the has_error()-gated boundary in `analyze_function`,
        // sqlite3InitOne's `body_text` spanned its own source AND both
        // swallowed siblings, so these plain text scans (returns_allocation,
        // never_returns) would wrongly flip true for sqlite3InitOne itself.
        let code = r#"int sqlite3InitOne(sqlite3 *db, int iDb, char **pzErrMsg, u32 mFlags){
  int rc;
  int i;
#ifndef SQLITE_OMIT_DEPRECATED
  int size;
#endif
  Db *pDb;
  char const *azArg[6];
  int meta[5];
  InitData initData;
  const char *zSchemaTabName;
  int openedTransaction = 0;
  int mask = ((db->mDbFlags & DBFLAG_EncodingFixed) | ~DBFLAG_EncodingFixed);

  assert( (db->mDbFlags & DBFLAG_SchemaKnownOk)==0 );
  assert( iDb>=0 && iDb<db->nDb );
  assert( db->aDb[iDb].pSchema );
  assert( sqlite3_mutex_held(db->mutex) );
  assert( iDb==1 || sqlite3BtreeHoldsMutex(db->aDb[iDb].pBt) );

  db->init.busy = 1;

  /* Construct the in-memory representation schema tables (sqlite_schema or
  ** sqlite_temp_schema) by invoking the parser directly.  The appropriate
  ** table name will be inserted automatically by the parser so we can just
  ** use the abbreviation "x" here.  The parser will also automatically tag
  ** the schema table as read-only. */
  azArg[0] = "table";
  azArg[1] = zSchemaTabName = SCHEMA_TABLE(iDb);
  azArg[2] = azArg[1];
  azArg[3] = "1";
  azArg[4] = "CREATE TABLE x(type text,name text,tbl_name text,"
                            "rootpage int,sql text)";
  azArg[5] = 0;
  initData.db = db;
  initData.iDb = iDb;
  initData.rc = SQLITE_OK;
  initData.pzErrMsg = pzErrMsg;
  initData.mInitFlags = mFlags;
  initData.nInitRow = 0;
  initData.mxPage = 0;
  sqlite3InitCallback(&initData, 5, (char **)azArg, 0);
  db->mDbFlags &= mask;
  if( initData.rc ){
    rc = initData.rc;
    goto error_out;
  }

  /* Create a cursor to hold the database open
  */
  pDb = &db->aDb[iDb];
  if( pDb->pBt==0 ){
    assert( iDb==1 );
    DbSetProperty(db, 1, DB_SchemaLoaded);
    rc = SQLITE_OK;
    goto error_out;
  }

  /* If there is not already a read-only (or read-write) transaction opened
  ** on the b-tree database, open one now. If a transaction is opened, it 
  ** will be closed before this function returns.  */
  sqlite3BtreeEnter(pDb->pBt);
  if( sqlite3BtreeTxnState(pDb->pBt)==SQLITE_TXN_NONE ){
    rc = sqlite3BtreeBeginTrans(pDb->pBt, 0, 0);
    if( rc!=SQLITE_OK ){
      sqlite3SetString(pzErrMsg, db, sqlite3ErrStr(rc));
      goto initone_error_out;
    }
    openedTransaction = 1;
  }

  /* Get the database meta information.
  **
  ** Meta values are as follows:
  **    meta[0]   Schema cookie.  Changes with each schema change.
  **    meta[1]   File format of schema layer.
  **    meta[2]   Size of the page cache.
  **    meta[3]   Largest rootpage (auto/incr_vacuum mode)
  **    meta[4]   Db text encoding. 1:UTF-8 2:UTF-16LE 3:UTF-16BE
  **    meta[5]   User version
  **    meta[6]   Incremental vacuum mode
  **    meta[7]   unused
  **    meta[8]   unused
  **    meta[9]   unused
  **
  ** Note: The #defined SQLITE_UTF* symbols in sqliteInt.h correspond to
  ** the possible values of meta[4].
  */
  for(i=0; i<ArraySize(meta); i++){
    sqlite3BtreeGetMeta(pDb->pBt, i+1, (u32 *)&meta[i]);
  }
  if( (db->flags & SQLITE_ResetDatabase)!=0 ){
    memset(meta, 0, sizeof(meta));
  }
  pDb->pSchema->schema_cookie = meta[BTREE_SCHEMA_VERSION-1];

  /* If opening a non-empty database, check the text encoding. For the
  ** main database, set sqlite3.enc to the encoding of the main database.
  ** For an attached db, it is an error if the encoding is not the same
  ** as sqlite3.enc.
  */
  if( meta[BTREE_TEXT_ENCODING-1] ){  /* text encoding */
    if( iDb==0 && (db->mDbFlags & DBFLAG_EncodingFixed)==0 ){
      u8 encoding;
#ifndef SQLITE_OMIT_UTF16
      /* If opening the main database, set ENC(db). */
      encoding = (u8)meta[BTREE_TEXT_ENCODING-1] & 3;
      if( encoding==0 ) encoding = SQLITE_UTF8;
#else
      encoding = SQLITE_UTF8;
#endif
      sqlite3SetTextEncoding(db, encoding);
    }else{
      /* If opening an attached database, the encoding much match ENC(db) */
      if( (meta[BTREE_TEXT_ENCODING-1] & 3)!=ENC(db) ){
        sqlite3SetString(pzErrMsg, db, "attached databases must use the same"
            " text encoding as main database");
        rc = SQLITE_ERROR;
        goto initone_error_out;
      }
    }
  }
  pDb->pSchema->enc = ENC(db);

  if( pDb->pSchema->cache_size==0 ){
#ifndef SQLITE_OMIT_DEPRECATED
    size = sqlite3AbsInt32(meta[BTREE_DEFAULT_CACHE_SIZE-1]);
    if( size==0 ){ size = SQLITE_DEFAULT_CACHE_SIZE; }
    pDb->pSchema->cache_size = size;
#else
    pDb->pSchema->cache_size = SQLITE_DEFAULT_CACHE_SIZE;
#endif
    sqlite3BtreeSetCacheSize(pDb->pBt, pDb->pSchema->cache_size);
  }

  /*
  ** file_format==1    Version 3.0.0.
  ** file_format==2    Version 3.1.3.  // ALTER TABLE ADD COLUMN
  ** file_format==3    Version 3.1.4.  // ditto but with non-NULL defaults
  ** file_format==4    Version 3.3.0.  // DESC indices.  Boolean constants
  */
  pDb->pSchema->file_format = (u8)meta[BTREE_FILE_FORMAT-1];
  if( pDb->pSchema->file_format==0 ){
    pDb->pSchema->file_format = 1;
  }
  if( pDb->pSchema->file_format>SQLITE_MAX_FILE_FORMAT ){
    sqlite3SetString(pzErrMsg, db, "unsupported file format");
    rc = SQLITE_ERROR;
    goto initone_error_out;
  }

  /* Ticket #2804:  When we open a database in the newer file format,
  ** clear the legacy_file_format pragma flag so that a VACUUM will
  ** not downgrade the database and thus invalidate any descending
  ** indices that the user might have created.
  */
  if( iDb==0 && meta[BTREE_FILE_FORMAT-1]>=4 ){
    db->flags &= ~(u64)SQLITE_LegacyFileFmt;
  }

  /* Read the schema information out of the schema tables
  */
  assert( db->init.busy );
  initData.mxPage = sqlite3BtreeLastPage(pDb->pBt);
  {
    char *zSql;
    zSql = sqlite3MPrintf(db, 
        "SELECT*FROM\"%w\".%s ORDER BY rowid",
        db->aDb[iDb].zDbSName, zSchemaTabName);
#ifndef SQLITE_OMIT_AUTHORIZATION
    {
      sqlite3_xauth xAuth;
      xAuth = db->xAuth;
      db->xAuth = 0;
#endif
      rc = sqlite3_exec(db, zSql, sqlite3InitCallback, &initData, 0);
#ifndef SQLITE_OMIT_AUTHORIZATION
      db->xAuth = xAuth;
    }
#endif
    if( rc==SQLITE_OK ) rc = initData.rc;
    sqlite3DbFree(db, zSql);
#ifndef SQLITE_OMIT_ANALYZE
    if( rc==SQLITE_OK ){
      sqlite3AnalysisLoad(db, iDb);
    }
#endif
  }
  assert( pDb == &(db->aDb[iDb]) );
  if( db->mallocFailed ){
    rc = SQLITE_NOMEM_BKPT;
    sqlite3ResetAllSchemasOfConnection(db);
    pDb = &db->aDb[iDb];
  }else
  if( rc==SQLITE_OK || ((db->flags&SQLITE_NoSchemaError) && rc!=SQLITE_NOMEM)){
    /* Hack: If the SQLITE_NoSchemaError flag is set, then consider
    ** the schema loaded, even if errors (other than OOM) occurred. In
    ** this situation the current sqlite3_prepare() operation will fail,
    ** but the following one will attempt to compile the supplied statement
    ** against whatever subset of the schema was loaded before the error
    ** occurred.
    **
    ** The primary purpose of this is to allow access to the sqlite_schema
    ** table even when its contents have been corrupted.
    */
    DbSetProperty(db, iDb, DB_SchemaLoaded);
    rc = SQLITE_OK;
  }

  /* Jump here for an error that occurs after successfully allocating
  ** curMain and calling sqlite3BtreeEnter(). For an error that occurs
  ** before that point, jump to error_out.
  */
initone_error_out:
  if( openedTransaction ){
    sqlite3BtreeCommit(pDb->pBt);
  }
  sqlite3BtreeLeave(pDb->pBt);

error_out:
  if( rc ){
    if( rc==SQLITE_NOMEM || rc==SQLITE_IOERR_NOMEM ){
      sqlite3OomFault(db);
    }
    sqlite3ResetOneSchema(db, iDb);
  }
  db->init.busy = 0;
  return rc;
}

/*
** Initialize all database files - the main database file, the file
** used to store temporary tables, and any additional database files
** created using ATTACH statements.  Return a success code.  If an
** error occurs, write an error message into *pzErrMsg.
**
** After a database is initialized, the DB_SchemaLoaded bit is set
** bit is set in the flags field of the Db structure. 
*/
int sqlite3Init(sqlite3 *db, char **pzErrMsg){
  int i, rc;
  int commit_internal = !(db->mDbFlags&DBFLAG_SchemaChange);
  
  assert( sqlite3_mutex_held(db->mutex) );
  assert( sqlite3BtreeHoldsMutex(db->aDb[0].pBt) );
  assert( db->init.busy==0 );
  ENC(db) = SCHEMA_ENC(db);
  assert( db->nDb>0 );
  /* Do the main schema first */
  if( !DbHasProperty(db, 0, DB_SchemaLoaded) ){
    rc = sqlite3InitOne(db, 0, pzErrMsg, 0);
    if( rc ) return rc;
  }
  /* All other schemas after the main schema. The "temp" schema must be last */
  for(i=db->nDb-1; i>0; i--){
    assert( i==1 || sqlite3BtreeHoldsMutex(db->aDb[i].pBt) );
    if( !DbHasProperty(db, i, DB_SchemaLoaded) ){
      rc = sqlite3InitOne(db, i, pzErrMsg, 0);
      if( rc ) return rc;
    }
  }
  if( commit_internal ){
    sqlite3CommitInternalChanges(db);
  }
  return SQLITE_OK;
}

void *extra_leak_marker(void){
  void *buf = malloc(4);
  free(buf);
  abort();
}"#;
        let summaries = parse_and_summarize(code);
        let outer = summaries
            .get("sqlite3InitOne")
            .expect("sqlite3InitOne should still get its own summary");
        assert!(
            !outer.returns_allocation,
            "sqlite3InitOne's summary was contaminated with extra_leak_marker's malloc() call"
        );
        assert!(
            !outer.never_returns,
            "sqlite3InitOne's summary was contaminated with extra_leak_marker's abort() call"
        );
        // Both swallowed siblings must still get their own, correctly-scoped summaries.
        assert!(summaries.contains_key("sqlite3Init"));
        let marker = summaries
            .get("extra_leak_marker")
            .expect("extra_leak_marker should get its own summary entry");
        assert!(marker.returns_allocation);
        assert!(marker.never_returns);
    }

    /// mbedtls's `mbedtls_platform_zeroize` reaches memset only through a
    /// volatile function pointer, under one of several `#if` arms, and is
    /// itself under `#if !defined(..._ALT)`. It clears its first parameter
    /// by every one of those routes, and nothing about its name may be
    /// needed to know so.
    #[test]
    fn clears_params_sees_through_volatile_pointer_and_preproc_arms() {
        let code = r#"
        #include <string.h>
        static void *(*const volatile memset_func)(void *, int, size_t) = memset;
        #if !defined(PLATFORM_ZEROIZE_ALT)
        void platform_zeroize(void *buf, size_t len) {
            if (len > 0) {
        #if defined(HAS_EXPLICIT_BZERO)
                explicit_bzero(buf, len);
        #elif defined(_WIN32)
                SecureZeroMemory(buf, len);
        #else
                memset_func(buf, 0, len);
        #endif
            }
        }
        #endif
        void forced_memzero(void *ptr, size_t len) {
            memset_func(ptr, 0, len);
        }
        void log_len(void *buf, size_t len) {
            (void)buf;
            (void)len;
        }
        void clears_other(void *buf, size_t len) {
            static char scratch[8];
            memset(scratch, 0, len);
        }
        "#;
        let summaries = parse_and_summarize(code);
        assert!(summaries["platform_zeroize"].clears_params.contains(&0));
        assert!(!summaries["platform_zeroize"].clears_params.contains(&1));
        assert!(summaries["forced_memzero"].clears_params.contains(&0));
        assert!(summaries["log_len"].clears_params.is_empty());
        assert!(summaries["clears_other"].clears_params.is_empty());
    }

    /// A wrapper that forwards its buffer to a clearer clears it too, and
    /// an object-like alias of a library clearer counts at the edge: the
    /// alias map is the project's, so the `#define` need not be in this
    /// file.
    #[test]
    fn clears_params_propagates_through_forwarding_and_aliases() {
        let code = r#"
        void zeroize(void *buf, unsigned long len) { memset(buf, 0, len); }
        void wipe(void *p, unsigned long n) { zeroize(p, n); }
        void wipe_twice(void *p, unsigned long n) { wipe(p, n); }
        void port_wipe(void *p, unsigned long n) { port_memset(p, 0, n); }
        void wipe_second(void *a, void *b, unsigned long n) { zeroize(b, n); }
        "#;
        let mut summaries = parse_and_summarize(code);
        let mut aliases = HashMap::new();
        aliases.insert("port_memset".to_string(), "memset".to_string());
        propagate_transitive_clears(&mut summaries, &aliases);
        assert!(summaries["wipe"].clears_params.contains(&0));
        assert!(summaries["wipe_twice"].clears_params.contains(&0));
        assert!(summaries["port_wipe"].clears_params.contains(&0));
        assert_eq!(
            summaries["wipe_second"].clears_params,
            HashSet::from([1usize])
        );
    }
}
