# hostap real-bug list — mainline triage (task 399)

Triages every item in `REAL_BUGS_FOUND.md` (109 line items, originally pinned
to commit `dcee60436390dd34731560657c4257c3b4c839a6`) against a live clone of
current hostap mainline: `~/data-enterprise/hostap-main`, HEAD `b9562516f`
(2026-08-24). Triage done via 7 parallel agents, one per report section, each
reading the actual current source (not pattern-matching the old description).

**This is step 1 of task 399's 4-step plan only** (diff against mainline,
triage still-present/fixed/changed). Steps 2 (deep reachability/severity
re-verification of survivors, esp. section 1) and 3 (draft actual upstream
disclosure) are NOT done — see the open follow-up task filed alongside this
file.

**2026-09-08 UPDATE:** steps 2-3 happened (see `data/precision_audit/hostap/`
disclosure package, todo-sqlite-cli tasks 587/588). 8 of section 1's items
(1, 4, 5, 6, 7, 9, 14, 16) were disclosed privately to Jouni Malinen on
2026-08-25 and he applied all 8 patches to upstream main on 2026-09-08 (git
am, author preserved as the discloser, committer Jouni Malinen). No separate
security advisory was published — maintainer judged impact too small,
doubting practical reachability of items 1, 14 and 16 specifically, but
applied the fixes anyway as defense-in-depth. Their "STILL PRESENT" rows
below are stale as of 2026-09-08; see the Section 1 table for per-item fixing
commits.

## Totals

| Outcome | Count |
|---|---|
| STILL PRESENT (verbatim) | 87 (96 as of the 2026-08-25 snapshot; 8 fixed 2026-09-08 via our disclosure, 1 (#15) found already fixed pre-filing) |
| Still present, but described location/detail changed (code moved/partially refactored — underlying defect unchanged) | 3 (#45, #65, #75) |
| ALREADY FIXED upstream | 17 (#2, #3, #8, #10, #11, #22, #54, #56 pre-existing; #15 fixed pre-filing per w1.fi advisory 2026-3, mislabeled STILL PRESENT below; #1, #4, #5, #6, #7, #9, #14, #16 via our 2026-08-25 disclosure, fixed 2026-09-08) |
| Indeterminate — original notes too thin to relocate | 2 (#95, #109) |
| **Total** | **109** |

Section 1 (attacker-reachable wire-data bugs, the highest-priority class) as
of the original 2026-08-25 snapshot: **11 of 16 still unfixed**. As of
**2026-09-08, only 2 of 16 remain unfixed** (#12, #13 — both confirmed prior
sqc TPs; task 587 judged both not reachable, so neither was ever filed). #15
is stale as STILL PRESENT below — task 698's advisory cross-check found it
was already fixed *before* our 2026-08-25 filing (w1.fi advisory 2026-3,
commit `f12d55ff652ab2e367425c1392510d10d8b9f638`), which is why it wasn't
included in the disclosure package either. Item #10 was fixed the same day
as the clone's HEAD (commit `3b573f29e`); items #1/#4/#5/#6/#7/#9/#14/#16
were fixed via our disclosure on 2026-09-08 (see per-item commits below).

## Already-fixed items (do not include in any future disclosure)

| # | Fixing commit | Date | Subject |
|---|---|---|---|
| 2 | `e6ab650d6` | 2026-07-13 | PR: Fix a possible buffer overflow in struct pr_channels |
| 3 | `41c86a2eb` | 2026-03-31 | (ML element length bound added to wpas_ml_parse_assoc) |
| 8 | `1d86c3172` | 2026-05-05 | TDLS: Fix potential read after the end of TDLS teardown frame |
| 10 | `3b573f29e` | 2026-08-24 | (adv_len >= svc_len guard added to wpas_sd_req_asp) |
| 11 | `aa02cfa56` | 2026-08-14 | RADIUS: Fix Message-Authenticator attribute validation |
| 22 | `b316612ff` | 2026-05-11 | SAE-PK: Add bounds check for fingerprint_bits |
| 54 | `0151b5d92` | 2026-06-17 | hostapd: Validate domain name length before assignment |
| 56 | `0ef6f792c` | 2026-07-09 | Fix hostapd.conf parser checks for HE SPR bitmaps |

## Section 1 — attacker-reachable wire-data (16 items, 11 still present)

| # | Status | Current location | Notes |
|---|---|---|---|
| 1 | FIXED (our disclosure) | `src/ap/wpa_auth_ft.c:2419-2430` `wpa_ft_process_rdie` | `fcae90b60` 2026-09-08. Was: check `end - pos < sizeof(*rdie)` but write 2 header bytes + `sizeof(*rdie)`; off-by-2. Maintainer doubts practical reachability (extra buffer room in frame construction) but applied fix anyway. |
| 2 | FIXED | — | `e6ab650d6` 2026-07-13 |
| 3 | FIXED | — | `41c86a2eb` 2026-03-31 |
| 4 | FIXED (our disclosure) | `src/common/ieee802_11_common.c:3845-3898` `get_max_nss_capability` | `895fd5881` 2026-09-08. Was: reads `optional[0..7]` when `bw==160/80P80` even if elem is only `HE_CAPABILITIES_ELEM_MIN_LEN`(21) bytes. |
| 5 | FIXED (our disclosure) | `src/ap/ieee802_11_eht.c:2310-2311` `hostapd_parse_link_reconf_req_sta_profile` | `652a34915` 2026-09-08. Was: `sta_info==end` boundary dereferenced before the bound check; 1-byte OOB read. |
| 6 | FIXED (our disclosure) | `src/ap/ieee802_11_he.c:472-480` `copy_sta_he_capab` | `6cf41afd5` 2026-09-08. Was: `check_valid_he_mcs()` called before the IE-length validation (via `||` short-circuit order). |
| 7 | FIXED (our disclosure) | `src/ap/drv_callbacks.c:1841-1857` `hostapd_action_rx` (CONFIG_NAN_USD) | `7ce112433` 2026-09-08. Was: checked only `plen>=5`, needed `>=6`. |
| 8 | FIXED | — | `1d86c3172` 2026-05-05 |
| 9 | FIXED (our disclosure) | `src/eap_server/eap_server_peap.c:834-903` (SoH vendor-TLV) | `4b5965e61` 2026-09-08. Was: checked `tlv_len<4` but read a 4-byte header needing `tlv_len>=8`. |
| 10 | FIXED | — | `3b573f29e` 2026-08-24 (fixed the same day as our mainline clone's HEAD) |
| 11 | FIXED | — | `aa02cfa56` 2026-08-14 |
| 12 | STILL PRESENT (confirmed prior sqc TP) | `src/eap_server/eap_server.c:596-621` | `len -= sizeof(*nak)` underflow, no preceding bound check. |
| 13 | STILL PRESENT (confirmed prior sqc TP) | `src/common/nan_de.c:1850-1867` `nan_check_bloom_filter` | `crc %= bf_len*8` unguarded against `bf_len==0`. |
| 14 | FIXED (our disclosure) | `src/common/nan_de.c:2686-2707` + `:961` | `ec339318a` 2026-09-08. Was: only rejected `n_max<n_min`, not equality; mod-by-zero when equal. Maintainer: input is internally-generated, doubts practical reachability. |
| 15 | FIXED (stale here — see task 698) | `src/common/sae.c:1902-1914` `sae_parse_token_container` | This row's STILL PRESENT was wrong even at 2026-08-25 triage time: task 698's advisory cross-check found the NULL guard was already added via w1.fi advisory 2026-3, commit `f12d55ff652ab2e367425c1392510d10d8b9f638`, before this triage ran. Not included in our disclosure package for that reason. |
| 16 | FIXED (our disclosure) | `src/eap_server/eap_server_ttls.c:1212-1249` | `95e57025f` 2026-09-08. Was: off-by-one length check; writer still always emits >=2 bytes so practically unreachable, as originally noted -- maintainer agrees, applied as defense-in-depth, and also added a check on the following id_len-bounded memcpy (same reasoning: unreachable but cheap to harden). |

## Section 2 — other reachable memory-safety/crypto bugs (11 items, 10 still present)

Items 17-21, 23-27 all STILL PRESENT verbatim (D-Bus invalid-free, privsep
overflow-check bypass, proc_coord stack overflow, l2_packet_privsep garbage
dest-addr, legacy NDIS/BSD driver bugs, libtomcrypt encrypt/decrypt swap,
driver_wired fd leaks — some worse than originally counted, e.g. #27's
leak list is longer than "6" once every failure branch is walked).
Item 22 (SAE-PK fingerprint overflow) is FIXED (`b316612ff`).

## Section 3-4 — NULL-deref / double-free (16 items, all 16 still present)

Every item (28-43) confirmed still present verbatim in current mainline.
Several files relocated (`src/tls/*`→`src/crypto/*`, `src/xml/*`→`src/utils/*`,
`src/ap/rrm.c`→`wpa_supplicant/rrm.c`, `eap_server_sim.c` moved from
`eap_peer/` to `eap_server/`) but no logic changed. Item 37 got a cosmetic
OpenSSL accessor-API refactor (`141abf49a`) that left the missing NULL check
untouched. Item 43 (eapol_test.c double-free) independently confirmed via
`eapol_sm_init()`'s own doc comment.

## Section 5 — broken error contracts / logic bugs (12 items, 9 present, 1 fixed, 1 changed)

Items 44, 46-53, 55 STILL PRESENT. Item 54 (ANQP domain-name truncation)
FIXED (`0151b5d92`). Item 45 (`pr_pasn_handle_auth_3`) is BEHAVIOR CHANGED:
current code already has a final `else` clause (added by `efe071081`,
predating even the audit's pinned commit — the original finding's premise
was already stale at write time), but a related issue survives: the
`pasn_result` callback fires with `dev->final_op_channel`/`final_op_class`
*before* the protocol_type validation that would reject bad values.

## Section 6-8 — OOB-write / sensitive-data hygiene / signal-handler (12 items, 10 present, 1 fixed, 1 relocated)

Item 56 (HE SPR bitmap OOB write) FIXED (`0ef6f792c`). Items 57-64, 66, 67
STILL PRESENT verbatim. Item 65 (DPP backup password zeroization) relocated
(`wpa_supplicant/dpp_backup.c` → `src/common/dpp_backup.c`) but bug
unchanged. Items 61/62 (prior confirmed sqc TPs) both reconfirmed present.

## Section 9 — resource/memory leaks (26 items, 25 present, 1 partially fixed)

Items 68-74, 76-93 STILL PRESENT verbatim (several file relocations noted,
no logic changes). Item 75 (`src/ap/beacon.c` SAE-offload leaks) is
PARTIALLY FIXED: the 3 `head`/`tail`/`resp` leaks were fixed by `37a2610f6`
(2026-03-17, "AP: Fix memory leaks in SAE offload error cases"), but the
narrower `link_params.resp` leak in `hostapd_gen_per_sta_profiles` (a
distinct function in the same file) is still present and was NOT covered by
that fix. Items 81 and 92 are mis-filed under "leaks" in the original report
— they're actually an OOB write and a double-free respectively, both
confirmed still present.

## Section 10 — lower-severity/misc (16 items, 14 present, 2 indeterminate)

Items 94, 96-108 STILL PRESENT verbatim (including item 107's Windows
CryptoAPI `BN_dup` unchecked-return, confirmed present though still
out-of-scope for the Linux oracle; item 108, a prior confirmed sqc TP,
reconfirmed). Items 95 and 109 marked INDETERMINATE — the original audit
notes for both lacked exact file/line citations to relocate confidently;
would need a fresh read of `eap_teap_common.c` from scratch to resolve, not
attempted here to avoid a speculative false triage.

## Path relocations found (for anyone re-grepping old citations)

- `wpa_supplicant/tdls.c` → `src/rsn_supp/tdls.c`
- `src/radius/radius_client.c`'s verify functions → actually in `src/radius/radius.c`
- `src/tls/*` → `src/crypto/*` (tls_openssl.c, tls_gnutls.c, tls_wolfssl.c)
- `src/xml/*` → `src/utils/*` (xml_libxml2.c, xml-utils.c)
- `src/ap/rrm.c` → `wpa_supplicant/rrm.c`
- `src/eap_peer/eap_server_sim.c` → `src/eap_server/eap_server_sim.c`
- `wpa_supplicant/wpa_helpers.c` → `src/common/wpa_helpers.c`
- `wpa_supplicant/dpp_backup.c` → `src/common/dpp_backup.c`
- `wpa_supplicant/proc_coord.c` → `src/common/proc_coord.c`
- `wpa_supplicant/driver_privsep.c` → `src/drivers/driver_privsep.c`
- `http/http_curl.c` → `src/utils/http_curl.c`
- `src/tncc/tncc.c` → `src/eap_peer/tncc.c`
- `src/ap/robust_av.c` → `wpa_supplicant/robust_av.c`
- `src/mesh/mesh_rsn.c` → `wpa_supplicant/mesh_rsn.c`
- `wpa_supplicant/xml-utils.c` → `src/utils/xml-utils.c`
- `wpa_supplicant/hostapd_cli.c` → `hostapd/hostapd_cli.c`
- `wpa_supplicant/dpp_hostapd.c` → `src/ap/dpp_hostapd.c`
- `src/utils/module_tests/common_module_tests.c` → `src/common/common_module_tests.c`
- `examples/browser.c` → `src/utils/browser.c`
