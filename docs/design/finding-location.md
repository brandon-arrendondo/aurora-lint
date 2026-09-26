# Where does a finding live? Forwarded pointers under API00-C and EXP34-C

**Status:** research for a decision (2026-09-25). Nothing here changes a
rule or a label. The companion ADR draft is
`docs/adr/0012-where-a-finding-lives.md` (Proposed). Brandon decides.

## The question

A function receives a pointer and never dereferences it. It only forwards it:
to a callee, into an ops table, or to a callback a plugin can register. Where
is the violation, if there is one?

- **(a) Only at the dereference, for every rule.** A line that only forwards a
  pointer is never a site. This would overturn the API00-C forwarding convention
  ("forwarded to a dereferencing callee = TP at the forwarding function") and
  mean a re-pass of every API00-C TP that rests on it.
- **(b) The dereference-site rule belongs to EXP34-C.** aurora-lint 4bbf15d1
  (Brandon, 2026-09-21) moved EXP34-C off the caller: a caller passing a
  possibly-null pointer to a project function never violates EXP34-C by
  itself. API00-C asks a different question: does an API function validate
  what it receives? Under (b), an exported function that passes an unchecked
  pointer into a callee it cannot vouch for is an API00-C TP at that function,
  and the forwarding convention stays. Brandon leans (b).

### Live cases

- hostap `wpa_supplicant/autoscan.c:143`: `scan_res` forwarded to the
  `notify_scan` ops callback. Labeled TP.
- hostap `wpa_msg`, `wpa_msg_ctrl`, `wpa_msg_global`, `hostapd_logger`: an
  opaque `void *ctx` forwarded only to callbacks registered through
  `wpa_msg_register_cb`. Labeled FP.
- hostap `wpa_supplicant_cancel_scan`: held.

These stay as labeled until the decision.

### Why it keeps coming back

The same function shape has been labeled both ways, depending on which rule
and which standard a pass applied:

- **An API00-C re-audit (2026-08).** Flipped 3,306 of 4,891 reviewed
  API00-C FPs to TP.
- **A pointer-parameter sample (2026-09-03).** Named the convention. A 59-row TP
  class, "param-forwarded-to-dereferencing-callee", was structurally identical
  at the flagged function to a 34-row FP mass: never dereferenced, validated
  in a called helper, callback pointer stored and not invoked, or forwarded to
  a null-tolerant sink. Only the callee's body separated them. That task's
  note: the original labeling "evidently stopped at 'not dereferenced here',
  which is right 22 times and wrong 59 times."
- **The API00-C labeling standard (2026-09-07/08).** The confirmed API00-C standard:
  per flagged parameter, a genuine guard on the parameter, every call site
  passing an address-of or literal, or forwarding only to null-tolerant
  callees. A parameter forwarded to a dereferencing callee is unvalidated.
- **The EXP34-C site ruling (2026-09-21), aurora-lint 4bbf15d1.**
  EXP34-C was relocated to the callee's own unguarded dereference, and 60 TP
  rows keyed at a caller's positional argument were corrected.
- **The ADR-0011 re-passes (2026-09-24/25).**
  Caller-side checks, proof chains, libraries and exported executables as
  external. These re-derived API00-C under that standard, forwarding
  convention included.

**Prior calls by the author of this document.** The adjudicating node that
wrote this made several of these calls, and they are flagged so a
reader can discount for them:

- **Its share of the API00-C rewrite** (sqlite, curl, mosquitto, lua, raylib, sel4,
  pureftpd). It applied the labeling standard, including "a parameter forwarded to
  a dereferencing callee is unvalidated"
  (`correction-api00c-644-sqlite-b1-task1541` notes).
- **The caller-check pass,** which kept that convention.
- **The library-ruling pass.** It applied the 4bbf15d1 site rule to EXP34-C keys: a plain
  `f(p)` into a project function stays FP, while `&p->f` is a dereference by
  the strict reading. It left the API00-C forwarding convention in place.

In other words, the author has already been applying (b) in practice. The
evidence below is presented for both options regardless.

## Evidence

Research notes with full source lists: two agent passes (CERT text and tools;
benchmarks and literature), summarized here with citations. Items marked
*(unverified)* could not be read in a primary source.

### 1. What CERT itself says

**API00-C, "Functions should validate their parameters" (recommendation).**
[CERT C, API00-C][api00]

- **The recommendation text** concedes that the usual C discipline is
  validation "on only one side of each interface". It then decides: "For
  safety and security reasons, this standard recommends that the called
  function validate its parameters."
- **The noncompliant example never dereferences its parameter.**
  `setfile(FILE *file)` only stores `file` for a later `usefile()`. The
  compliant solution adds validation in `setfile`, the function that does
  not dereference. This is the store/register form of forwarding, and CERT
  places the violation at the receiving function.
- **Risk assessment:** Medium, Unlikely, **Detectable: No**, Repairable: No,
  P2, **L3**.
- **Related guideline:** CWE-20.
- **No stated scope.** The page does not say "exported" or "external". The
  scope to API/library functions comes from the section it sits in and the
  example's "library" wording.

**EXP34-C, "Do not dereference null pointers" (rule).** [CERT C, EXP34-C][exp34]

- **Two of three noncompliant examples put the site at a forwarding call.**
  In each, the function only passes the parameter to a *library* callee:
  `strlen(input_str)` in `f`, and `memcpy(..., user_data, ...)` in the
  libpng example. The compliant solutions add `if (NULL == param)` in that
  function. CERT's words: "Passing a null pointer to memcpy() would produce
  undefined behavior, even if the number of bytes to copy were 0."
- **So EXP34-C does not follow (a) either.** A forwarding call is the site
  when the callee's contract makes null undefined. aurora-lint 4bbf15d1
  already keeps that exception for libc dereferencing callees.
- **Risk assessment:** High, Likely, Detectable: No, P18, L1.

**Rules versus recommendations.** [CERT C, Introduction][rvr]

- A rule must not rely on "assumptions", and must be checkable by automated
  analysis, formal methods or inspection.
- A recommendation is used when one of those criteria cannot be met, and
  which recommendations to adopt "depends on the requirements of the final
  software product".
- API00-C being a Detectable: No recommendation fits a guideline whose
  verdict depends on assumptions about who calls the function.

### 2. How tools locate these findings

| Tool / checker | Primary line | Flags a bare forwarder with no null evidence? |
|---|---|---|
| Coverity FORWARD_NULL (`var_deref_model`) | the call line passing a known-null value | No |
| Klocwork NPD.FUNC.CALL.MUST / NPD.CHECK.CALL.* | the call line passing the value | No (needs a null source) |
| Klocwork NPD.FUNC.MUST / NPD.CHECK.MUST | the dereference | No |
| Infer Pulse NULLPTR_DEREFERENCE | the caller's call site where a latent issue becomes manifest | No |
| Clang core.NullDereference / core.NonNullParamChecker | the dereference / a call into a `nonnull` parameter | No |
| GCC -Wanalyzer-(possible-)null-argument | a call into a `nonnull` parameter | No |
| cppcheck ctunullpointer | the callee's dereference, with a note per forwarding call | No |
| Frama-C Eva | the dereference (`\valid` assertion) | No |
| Polyspace Bug Finder / Code Prover | the dereference | No |
| **Polyspace CERT API00-C "Unchecked Pointer Access" (R2026b)** | read, write **or assignment** of an unchecked pointer parameter | **Partly: a store-only function is flagged; a call argument is undocumented** |
| CodeSonar LANG.STRUCT.UPD | the parameter's dereference | No |
| Parasoft CERT_C-API00-a | per function ("validity of parameters must be checked inside each function") | Unknown *(unverified)* |
| MISRA C Dir 4.11 (Polyspace) | the library call site | Library callees only; Helix QAC lists it "Unassisted" |

Sources: [Coverity trace, haproxy #634][cov]; Klocwork
[NPD.FUNC.CALL.MUST][kw1], [NPD.CHECK.MUST][kw2]; [Infer Pulse][pulse];
[Clang checkers][csa]; [GCC analyzer][gcc]; cppcheck
[`ctu.cpp`][cppcheck]; [Frama-C Eva manual §3.2, §6.3][eva]; Polyspace
[API00-C][ps-api00], [null deref][ps-npd], [Dir 4.11][ps-d411];
[CodeSonar LANG.STRUCT.UPD][cs-upd]; [Helix QAC MISRA table][qac]. The
official Coverity docs could not be fetched, so its checker semantics beyond
the trace example are *(unverified)*.

Three things follow from the table:

1. **No dereference-based tool reports a forwarder on its own.** When they
   report across calls, they anchor either at the frame that has the null
   evidence (Coverity, Klocwork, Infer, Clang, GCC) or at the dereference,
   with forwarding frames as trace notes (cppcheck, Eva). That matches
   aurora-lint's current EXP34-C (4bbf15d1) exactly.
2. **The API00-C claimants split.** CodeSonar's mapping is
   dereference-anchored. Polyspace's new API00-C checker is not, and flags an
   unchecked store of a parameter. That is the shape of CERT's `setfile`, and
   the closest tool precedent for (b). No surveyed tool documents flagging a
   pure call-argument forward under API00-C.
3. **Tools that report at a call do so only when the callee's contract is
   known:** a library function, a `nonnull` parameter, or (FindBugs, below)
   a callee proven to always dereference.

### 3. Benchmarks

**Juliet C/C++ 1.3, CWE-476 and CWE-690** (read from the local checkout's
`manifest.xml`, sources and User Guide). All 1,452 flaw lines were classified:

| Kind of line | Count |
|---|---|
| Operator dereference (CWE-476 330, CWE-690 720) | 1,050 |
| Call into a libc function (`strcpy`, `wcscpy`, `fclose`; all CWE-690) | 384 |
| Null check after a dereference (CWE-476) | 18 |

**No flaw line is a call into a user-defined forwarder.** In
`CWE476_..._int_54`, the files `_54b`, `_54c` and `_54d` are bare forwarders
with no flaw and no FLAW comment; only `_54e.c:27` (`printIntLine(*data)`) is
a flaw. The function-pointer variants `_44` and `_65` place the flaw at the
dereference inside the target function, not at `funcPtr(data)`.

**Juliet has no CWE-20 at all** (0 manifest flaws), so no benchmark supplies
ground truth for a parameter-validation finding.

**Scoring caveat.** User Guide §8.1 scores by function name, not line: any
CWE-476 report inside a `*bad*` function is a TP. A report at the forwarder
`_54b_badSink` would score TP there, but FP plus FN under a line-exact scorer.

**NIST SATE / Ockham.** [NISTIR 8113][ockham] (SATE V Ockham Sound Analysis
Criteria, Black & Ribeiro, 2016):

- **§2.2, what a site is.** A site is "the last place in code that the
  programmer may make necessary checks". A `strcpy()` call is a site because
  the library cannot check.
- **§3.4.4, the CWE-476 site:** "Use of unary *, ->, or [] operators". Some
  library calls should be added.
- **§4.2, missing checks:** "The question is still open as to what should be
  declared to be the site of missing code, such as failure to check user
  input."
- **§2.1, tentative warnings.** "caution: this function does not check for a
  null" reports are "at best ignored".

[SATE IV, SP 500-297][sate4] §2.6 and §2.9.6:

- It matches Juliet warnings at block level.
- It accepts "same weakness instance, different perspective", with the
  example of a tool reporting an unchecked return rather than the null
  dereference.
- Tools "usually report locations in the neighborhood of the sink".

### 4. Literature

**Null-dereference analyses anchor at the dereference or at a known-contract
call.**

- [Hovemeyer & Pugh, PASTE 2007][hp] §3.3, §4.1. FindBugs treats passing a
  value to a parameter "that must be non-null" as a dereference, and derives
  parameters "always dereferenced (or passed to methods that, in turn,
  dereference them)". It reports the null origin plus the dereference
  location.
- [Engler et al., SOSP 2001][engler] §7. A checker that warned whenever a
  tainted value "was passed as a function parameter, rather than checking if
  the call actually dereferenced the value" produced too many false
  positives. This is direct evidence against flagging bare forwarding
  *without knowing the callee*.
- [Infer Pulse docs][pulse] and [Le et al., OOPSLA 2022 §2.3][pulsex]. An
  error that depends on a parameter is "latent" and not reported. On OpenSSL:
  "it seems undesirable to report latent null-pointer-dereferences (NPEs) to
  a programmer". Pulse-X reports latent NPEs only in `main()`, the true
  external entry point.
- The Pulse-X result is the strongest evidence against flagging internal
  forwarders. It is also evidence *for* treating external entry points
  differently, which is what (b)'s exported-function scope does.

**Design by contract vs defensive programming.**

- [Meyer, IEEE Computer 1992][meyer], on who should check a precondition:
  "There is no absolute rule." Checking in both places is rejected.
- CERT API00-C picks the callee "for safety and security reasons".
- GCC's `nonnull` puts the obligation on the caller and warns about a
  defensive check in the callee ([GCC attributes][gccattr]).
- So "validate on one side" is a design choice. API00-C is CERT's
  recommendation of which side, not a statement that the other side is a
  defect.

**Developer understanding.**

- [Bessey et al., CACM 2010][bessey]: "If people don't understand an error,
  they label it false."
- [Johnson et al., ICSE 2013][johnson]: 19 of 20 participants said tools do
  not explain enough.
- [Sadowski et al., Tricorder, ICSE 2015][tricorder]: the effective false
  positive.
- A forwarding-site report whose failure lives in another function is harder
  to act on unless it names the callee and the path. aurora-lint's API00-C
  message names only the parameter.

**No published evaluation of API00-C- or CWE-20-style checkers for C was
found.** That is a gap in the search, not a proven absence.
[CWE-20][cwe20] is marked "DISCOURAGED" for vulnerability mapping.

## What the labels would do

Counted read-only from benchmark_adjudication `main` at `47a12dd`. Method:

- For every API00-C TP key, the flagged pointer parameters come from a fresh
  API00-C scan of each pinned corpus with the local release binary.
- Each parameter's uses in the function body are then classified with
  tree-sitter:
  - **dereference:** `p->`, `*p`, `p[i]`, or an argument to a dereferencing
    libc function;
  - **macro:** an argument to a function-like macro, which may dereference;
  - **forward:** an argument to any other call;
  - **other:** storage, comparison or return.
- A key is **forwarding-only** when no flagged pointer parameter has a
  dereference or macro use and at least one has a forward use.

This is a mechanical estimate. A 12-row hand check agreed on 11.

| Project | API00-C TP | With a pointer message | Forwarding-only | Some param forwarding-only | Dereferences |
|---|---|---|---|---|---|
| hostap | 3,483 | 3,164 | 478 | 349 | 2,337 |
| sqlite | 1,287 | 1,190 | 88 | 119 | 983 |
| curl | 753 | 735 | 93 | 111 | 531 |
| lua | 354 | 336 | 42 | 15 | 279 |
| sel4 | 311 | 256 | 91 | 20 | 145 |
| mosquitto | 291 | 286 | 18 | 24 | 244 |
| raylib | 242 | 178 | 30 | 3 | 145 |
| pureftpd | 39 | 39 | 10 | 4 | 25 |
| mbedtls | 31 | 29 | 5 | 1 | 23 |
| ventoy | 24 | 21 | 2 | 1 | 18 |
| valkey | 2 | 2 | 2 | 0 | 0 |
| **Total** | **6,817** | **6,236** | **859** | **647** | **4,730** |

- **Under (a), about 860 API00-C TPs flip to FP** (about 13% of API00-C TPs),
  concentrated in hostap. The 647 keys where only *some* flagged parameters
  are forwarding-only would not flip, because another flagged parameter is
  dereferenced unchecked.
- **By source batch,** the forwarding-only TPs come mostly from
  these batches in the public dataset: `task-644-full-reaudit` (196),
  `task-794-hostap` (82), `task-768-sel4` (80), `task-767-hostap` (68), the hostap
  `-rdynamic` corrections (99) and `task-769` (46).
- **Only 18 of the 859 forward into a function pointer or ops table** (curl
  12, hostap 4, sqlite 1, raylib 1). The ops-table/plugin case the live
  examples turn on is a small subset.
- **Under (b), no label moves.** The one inconsistency to resolve is the
  `wpa_msg` family (see below).
- **EXP34-C is not affected by either option.** It already follows the site
  rule (4bbf15d1). No EXP34-C TP rests on a bare forward into a project
  function after the site-rule corrections.

## The options, argued straight

### For (a)

- **Every dereference-based tool, Juliet, SATE/Ockham and the null-analysis
  literature agree:** a null-dereference finding lives at the dereference, or
  at a call into a callee with a known contract. A forwarding line into user
  code is not a site. Adopting (a) aligns aurora-lint's API00-C with how
  every other analyzer locates the same defect, and with every
  line-granular benchmark.
- **It gives one location per defect.** With the forwarding convention, one
  unchecked dereference in a leaf helper can make every exported wrapper
  above it an API00-C TP. That is several findings for one missing check,
  and each wrapper's report names only the parameter, not the callee.
  Bessey and Tricorder both predict developers treat such reports as false.
- **It removes a judgment call that has churned.** The forwarder's verdict
  depends on the callee's body, possibly several frames down (the pointer sample's note:
  "every row in this batch required reading the callee"). Under (a) the
  question is local.
- **Against (a):**
  - It contradicts CERT's own text. API00-C's noncompliant `setfile` never
    dereferences, and EXP34-C places its site at a forwarding call to
    `strlen`/`memcpy`.
  - Applied literally to "every rule", it would also break the libc
    exception 4bbf15d1 keeps.
  - It makes API00-C redundant with EXP34-C: a parameter-validation
    recommendation that only fires where EXP34-C already fires adds nothing.
  - It flips about 860 labels.

### For (b)

- **It is what CERT wrote.** API00-C recommends that "the called function
  validate its parameters", and its example is a non-dereferencing store.
  EXP34-C's examples put the site at the forwarding call when the callee
  cannot accept null.
- **Scoping it to exported functions matches the ADR-0011 rulings** on open
  caller sets. It also matches Pulse-X's one exception: latent
  parameter-dependent NPEs are reported at the true entry point.
- **It keeps two rules asking two questions.** EXP34-C asks "is null
  dereferenced here?" API00-C asks "does this entry point validate what it
  receives before handing it on?" That is ADR-0001's "report as written",
  applied to a recommendation whose purpose is the input boundary.
- **It has a tool precedent.** Polyspace's CERT API00-C checker flags an
  unchecked store of a parameter with no dereference.
- **No labels move.**
- **Against (b):**
  - No benchmark can score it. Juliet has no CWE-20, and Ockham calls the
    site of a missing check "still open".
  - Its verdict depends on the callee's body, which is the churn source.
  - No surveyed tool documents flagging a pure call-argument forward, so
    API00-C recall and precision figures under (b) have no external
    comparator.
  - API00-C is an L3, Detectable: No recommendation. Weighting it like a rule
    in headline precision overstates what it measures.

## Recommendation

**(b), made explicit and bounded.**

### EXP34-C: unchanged (4bbf15d1)

The site is the dereference, or a call into a callee whose contract forbids
null: a libc dereferencing function, or a `nonnull` parameter. A plain `f(p)`
into a project function is not an EXP34-C site. `&p->f` with `p` unproven is
a dereference (the strict reading of C11 6.5.2.3).

### API00-C: TP at the receiving function when

1. the function is externally reachable: non-static in a library or exported
   executable (ADR-0011's open caller set); and
2. the flagged pointer parameter is used without a validating test on some
   path; and
3. the use is one of:
   - a dereference;
   - passing it to a callee that dereferences it unchecked;
   - passing it to a callee whose body is not in the scanned source, or
     that is reached through a function pointer, ops table or registered
     callback. "The callee it cannot vouch for": this reads Brandon's (b)
     literally, and it is where the ops-table cases land;
   - storing it for later use (`setfile`).

### API00-C: FP when

- the function tests the parameter;
- or every use is null-tolerant as written (a null-tolerant callee, `free`);
- or the caller set is closed and every caller proves the value (ADR-0011).

### How the result is reported

- **Separately from EXP34-C,** with the site convention stated. Ockham §2.1
  allows a tool its own site definition "as long as it is expressed".
- **API00-C's figures are labeled as a recommendation-level measure** with no
  external benchmark.
- **Headline null-dereference precision/recall is EXP34-C's.**

### Open sub-question for Brandon: opaque context pointers

The `wpa_msg`/`hostapd_logger` family forwards a `void *ctx` only to
registered callbacks, and NULL is a legitimate value there (the callback may
not use it). Under the rule above, a registered callback is a callee the
function cannot vouch for, so these would be TP. They are labeled FP today.

The alternative is to treat an opaque `void *` that the API documents as
optional as "nothing to validate". That rests on the documented contract,
which is ADR-0011 basis 5 (inference). The rule above is the stricter
reading, and would flip that family to TP.

## Implications for the paper

- **Under (b):** state the site convention per rule in the methodology
  section. Report API00-C separately from EXP34-C, as a
  parameter-validation measure. Note that no benchmark provides ground truth
  for it and that the CERT risk level is L3. EXP34-C carries the
  null-dereference comparison with other tools, because its sites are the
  ones other tools and Juliet use.
- **Under (a):** API00-C's measured TP count drops by about 860 (about 13%).
  Its recall denominator shrinks the same way, and much of what remains
  duplicates EXP34-C sites. Its standalone value in the paper would need
  re-arguing.

## Unverified items to check before citing

- Official Coverity checker docs.
- The MISRA Dir 4.11 text (paywalled). It is recalled as allowing the check
  before the call, in the library function, or in a wrapper.
- Parasoft CERT_C-API00-a behaviour.
- PC-lint Plus 613/668 text.
- LDRA.
- The cppcheck primary-line claim (inferred from source).
- SATE V main report and SATE 2008 (404s).
- Dillig et al., the biabduction papers, Hoare.
- The exact Meyer OOSC wording.

[api00]: https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/application-programming-interfaces-api/api00-c
[exp34]: https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/expressions-exp/exp34-c
[rvr]: https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/front-matter/introduction/rules-versus-recommendations
[cov]: https://github.com/haproxy/haproxy/issues/634
[kw1]: https://help.klocwork.com/2024/en-us/reference/npd.func.call.must.htm
[kw2]: https://help.klocwork.com/2025.3/en-us/reference/npd.check.must.htm
[pulse]: https://fbinfer.com/docs/checker-pulse
[csa]: https://clang.llvm.org/docs/analyzer/checkers.html
[gcc]: https://gcc.gnu.org/onlinedocs/gcc/Static-Analyzer-Options.html
[cppcheck]: https://github.com/danmar/cppcheck/blob/main/lib/ctu.cpp
[eva]: https://www.frama-c.com/download/frama-c-eva-manual.pdf
[ps-api00]: https://www.mathworks.com/help/bugfinder/ref/certcrec.api00c.html
[ps-npd]: https://www.mathworks.com/help/bugfinder/ref/dereferenceofanullpointer.html
[ps-d411]: https://www.mathworks.com/help/bugfinder/ref/misrac2012d4.11.html
[cs-upd]: https://docs.adacore.com/live/wave/codesonar_manual/html/codesonar_manual/WarningClasses/LANG/LANG.STRUCT.UPD.html
[qac]: https://help.perforce.com/helix-qac/enforcement/doc/MISRA_M3CM.html
[ockham]: https://nvlpubs.nist.gov/nistpubs/ir/2016/NIST.IR.8113.pdf
[sate4]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.500-297.pdf
[hp]: https://www.cs.jhu.edu/~daveho/pubs/paste2007.pdf
[engler]: https://web.stanford.edu/~engler/deviant-sosp-01.pdf
[pulsex]: https://people.mpi-sws.org/~dreyer/papers/finding-real-bugs/paper.pdf
[meyer]: https://se.inf.ethz.ch/~meyer/publications/computer/contract.pdf
[gccattr]: https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html
[bessey]: https://web.stanford.edu/~engler/BLOC-coverity.pdf
[johnson]: https://petertsehsun.github.io/soen7481/papers/icse13b.pdf
[tricorder]: https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/43322.pdf
[cwe20]: https://cwe.mitre.org/data/definitions/20.html
