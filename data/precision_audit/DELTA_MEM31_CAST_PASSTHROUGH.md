# MEM31-C / MEM30-C delta: cast-stripping in `collect_param_passthroughs`

Task uuid `8896e5ba-6dab-4901-a20c-51785aaa9d10` (tools_sqc; display id 1034 at
time of writing, renumbered once already — cite the uuid).

Rule change: `cf22fb0a`, `collect_param_passthroughs` now routes each call
argument through `init_state::strip_arg_casts` before the identifier test, so a
cast-forwarded parameter produces a passthrough edge and
`propagate_transitive_frees` has something to walk. Consumers are MEM30-C and
MEM31-C.

## Local A/B (dev-921, all 9 pinned checkouts, `bench realworld-run --tool sqc`)

| | run | commit |
|---|---|---|
| baseline | 209 | `406a9c02` |
| after | 210 | `cf22fb0a` |

`corpus-check` clean before both runs (all 9 detached at pinned commits).

Whole-corpus delta is **one rule in one project**:

| rule | base | after | delta |
|---|---|---|---|
| MEM31-C | 2,795 | 2,732 | **−63** |
| MEM30-C | 239 | 239 | 0 |

Every other rule is flat. All 63 removed findings are in **hostap**; the other
eight checkouts are byte-identical.

**The predicted direction did not materialize.** The task expected an ADDING
delta (more transitive frees seen ⇒ more MEM30-C use-after-free). MEM30-C moved
by exactly zero on this corpus; the measured effect is suppression-only, via
MEM31-C no longer reporting a leak where the deallocator is now seen to free.

Shape of the removal: 63 raw findings across 53 `(file, line)` sites — 47 sites
cleared entirely (56 findings) and 6 sites that went from two findings to one
(7 findings).

## Mechanism (verified, not inferred)

`hostap/src/crypto/crypto_wolfssl.c:1365`

```c
void crypto_bignum_deinit(struct crypto_bignum *n, int clear)
{
	if (!n)
		return;
	if (clear)
		mp_forcezero((mp_int *) n);
	mp_clear((mp_int *) n);
	os_free((mp_int *) n);          /* <-- cast-forwarded free of the param */
}
```

`os_free` is hostap's own in-tree `free` wrapper, so the whole chain is
in-corpus. Pre-change the `(mp_int *)` cast meant no passthrough edge, so
`crypto_bignum_deinit` was not credited with freeing param 0, and every
`crypto_bignum_init()` released through it looked leaked at the call site.

**Caveat carried forward from the EXP33-C/EXP34-C cluster:** hostap defines
`crypto_bignum_deinit` **twice** — `crypto_wolfssl.c:1365` and
`crypto_openssl.c:2035` — and prescan summaries are keyed on the bare name, so
one body wins the collision. Here the answer is right either way (the OpenSSL
body cast-forwards to `BN_free`/`BN_clear_free`, also freeing the parameter),
but this is the same name-collision hazard flagged for curl's seven
`my_md5_init` definitions.

## What is NOT yet claimable

All 53 dropped sites are **unlabeled** in `ground_truth`. Measured precision and
recall are byte-identical across the two runs (19.2% / 94.3%), because the whole
delta sits outside the labeled denominator. So:

- **No precision/FP-reduction claim may be published for MEM31-C from this
  change** until the sites below are adjudicated.
- No labeled TP was lost, so there is no *evidence* of a recall regression —
  but absence of labels is not evidence of absence, which is exactly what the
  adjudication settles.

Scope: all five files are under `src/`, fully in-scope per
`data/precision_audit/hostap/README.md` (`src/` + `wpa_supplicant/` +
`hostapd/`). No out-of-scope filtering needed — unusually, 0% noise.

Gating check done: no other open MEM30-C/MEM31-C FP-reduction task exists in the
tools_sqc backlog, so this is not waiting on a cheaper fix that would shrink the
dump.

## Handoff

`data/precision_audit/hostap/delta_mem31_cast_passthrough_removed.csv` — 70
baseline rows at the 53 dropped sites, with `base_n`/`after_n` so a partially
cleared site is distinguishable from a fully cleared one.

Hypothesis to test, not a verdict: these read as FPs by construction, since the
deallocator demonstrably frees its parameter on both backends. The cases worth
real attention are sites where the leak was real for an *unrelated* reason — an
early return that skips the `crypto_bignum_deinit` call — which the transitive
credit would now mask.

Adjudication is `benchmarking_db`'s. dev-921 is off the VLAN, so runs 209/210
exist only in this checkout's SQLite; the CSV is the handoff.
