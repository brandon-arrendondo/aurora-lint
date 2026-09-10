# EXP34-C/EXP33-C true positives from bmdb task 1107 — verified against current mainline

**Codebase:** hostap, pinned commit `dcee60436390dd34731560657c4257c3b4c839a6`.
**Source:** delta-adjudication of EXP34-C findings attributable to tools_sqc commit
`d0802e08` ("1099", proven-nonnull widening), bmdb task 1107, 2026-09-10. 2047
findings adjudicated, 39 confirmed TP (1 EXP33-C, 38 EXP34-C).
**Mainline recheck:** 2026-09-10, r720, against `~/data-enterprise/hostap-main`,
per the discipline documented in `docs/upstream-disclosures.rst`: "re-verified
against current upstream mainline — not just cited at the audit's original
pinned commit — to avoid disclosing something already fixed." First pass used
the mirror's then-local HEAD (`183ee836daa672db2c632c06f68e9cc0ad164a60`,
2026-08-25) without fetching first — caught and corrected same-day: fetching
`origin` showed the local checkout was 125 commits behind, with origin/main's
tip dated 2026-09-10 (today). The local checkout also carries one commit
(`183ee836d`, a NAN mod-by-zero fix) and an untracked `tests/fuzzing/nan-de-poc/`
directory not present on origin — evidently someone else's local work, left
untouched rather than merged/discarded. Re-verified all 6 findings in the 6
files that changed between the stale local HEAD and true `origin/main`
(`9c4c3b076`, 2026-09-10) directly against `origin/main`'s content; all 6 hold
unchanged (see per-item notes below). The other 33 findings' files were
unaffected by the additional 125 commits, so the original check against local
HEAD stands for those without re-verification needed.

**Result: all 39 are STILL PRESENT on current trunk. None have been fixed
upstream.** This is the opposite outcome from the same recheck done on 2
sqlite EXP34-C TPs from this same task, both of which turned out already fixed
(see `../sqlite/poc/CONFIRMED_ALREADY_FIXED_fossildelta_rbu_null_deref.md`) —
recorded here as a genuine, not assumed, result: every file was individually
checked for commits since the pin, and every vulnerable code shape was read
directly on trunk before concluding.

**Not filed upstream by this session** — per the disclosure philosophy,
Brandon is the accountable filer; this batch is handed off as vetted
candidates, not auto-filed. One item (see below) duplicates an already-known,
not-yet-filed defect from the original 736-file audit (`REAL_BUGS_FOUND.md`
item 33) — flagged, not double-counted.

---

## Cross-check against the existing 109-item audit catalog

`REAL_BUGS_FOUND.md` (the original file-at-a-time audit's defect list) shares
several file paths with this batch. Checked each shared file for a
function-level match, not just a filename match:

| File | Existing catalog item | Same bug? |
|---|---|---|
| `src/crypto/tls_gnutls.c` | #33, `tls_connection_verify_peer` (catalog path listed as stale `src/tls/tls_gnutls.c` — confirmed only one real file exists) | **YES — same function, same bug** (see item 6 below) |
| `src/ap/dpp_hostapd.c` | #53, `hostapd_dpp_pb_pkex_init` (catalog path listed as stale `wpa_supplicant/dpp_hostapd.c`) | No — different function (`hostapd_dpp_auth_init`, item 1 below) |
| `src/utils/http_curl.c` | #80, `http_post` (catalog path listed as stale `http/http_curl.c`) | No — different function (`http_download_file`, item 15 below) |
| `src/utils/browser-android.c` | #96, dangling-stack-address bug at line 58 | No — different bug entirely (item 12 below is the `url` NULL-deref at lines 38/40/43) |
| `src/ap/hostapd.c` | #71, leak in `hostapd_init` | No — different function (item 2 below is `hostapd_reconfig_wpa`) |
| `src/common/proximity_ranging.c` | #2, #45, #88 — three separate known bugs in this file | No — none match `pr_prepare_pasn_pr_elem` (item 5 below) |
| `src/crypto/tls_wolfssl.c` | #74, leak in `tls_init` (catalog path stale) | No — different function (item 8 below is `tls_connection_get_eap_fast_key`) |
| `src/eap_server/eap_server_peap.c` | already-disclosed-and-fixed item (SoH vendor-TLV, `eap_server_peap.c:864-887`) | No — different function (item 9 below is `eap_peap_build_phase2_term`) |

**One duplicate found (item 6), all others are new, independent findings** —
several land in files the original audit already flagged for unrelated bugs,
which is expected in files this actively used/complex, not evidence of
overlap.

---

## Confirmed-live findings (39, all verified against trunk `183ee836d`)

Current trunk line cited where it shifted from the pinned commit's line;
"—" means unchanged.

| # | File | Pinned line | Trunk line | Defect | Reachability |
|---|---|---|---|---|---|
| 1 | `src/ap/dpp_hostapd.c` | 940 | — | `hostapd_dpp_auth_init()`: `own_bi` NULL when ctrl command omits `own=`; reaches unconditional `auth->own_bi->pubkey_hash` deref in `dpp_auth.c:1255`. | Local ctrl_iface `DPP_AUTH_INIT` command missing `own=` |
| 2 | `src/ap/hostapd.c` | 174 | 169 | `hostapd_reconfig_wpa()` ignores `wpa_reconfig()`'s return; OOM during reconfig leaves NULL `wpa_ie` + stale nonzero `wpa_ie_len`, reaching driver `set_generic_elem` unchecked. | OOM during config reload |
| 3 | `src/ap/wnm_ap.c` | 478 | — | `ieee802_11_rx_bss_trans_mgmt_query()`: possibly-NULL `hex` passed unconditionally as `%s` arg to `wpa_msg`, UB on non-glibc libc. | BSS Transition Management Query with empty candidate list |
| 4 | `src/ap/wpa_auth.c` | 1206, 1208 | 1245/1248/1250 (consolidated to one reused local) | `wpa_auth_sta_deinit()`: `wpa_get_primary_auth()` NULL for an MLD group with no `primary_auth` link; passed unguarded as `eloop_ctx`, deferred `wpa_rekey_gtk()` dereferences `wpa_auth->is_ml` unconditionally. | MLD group teardown timing |
| 5 | `src/common/proximity_ranging.c` | 1609 | 1711 | `pr_prepare_pasn_pr_elem()`: `pr_encaps_elem()` can return NULL (internal OOM); dereferenced unguarded via `wpabuf_len(buf2)`. | OOM during PASN ranging element prep |
| 6 | `src/crypto/tls_gnutls.c` | 1306 | — | `tls_connection_verify_peer()`: `buf = os_malloc(...)` unchecked before `wpa_printf(..., "%s", ..., buf)`. **Duplicates `REAL_BUGS_FOUND.md` item 33** — already known, not yet filed. | OOM during peer cert chain logging |
| 7 | `src/crypto/tls_openssl_ocsp.c` | 610, 612 | — | `ocsp_find_signer()`: `sk_X509_num(NULL)` returns -1, converts to `UINT_MAX` against unsigned loop index, runs `X509_pubkey_digest()` on NULL cert. | Malformed/misconfigured OCSP response, no issuer cert |
| 8 | `src/crypto/tls_wolfssl.c` | 2511, 2512, 2515, 2525, 2531 | 2509-2531 | `tls_connection_get_eap_fast_key()`: `wolfSSL_get_keys()`'s return discarded; `master_key`/`server_random`/`client_random` used unconditionally. | Aborted/failed TLS handshake |
| 9 | `src/eap_server/eap_server_peap.c` | 526, 532 | — | `eap_peap_build_phase2_term()`: `eap_server_tls_encrypt()` result never NULL-checked; dereferenced on the EAP-PEAP TLS 1.3 session-resumption path. | TLS 1.3 session resumption + encryption failure |
| 10 | `src/drivers/driver_nl80211_event.c` | 3647 | 3889 | `nl80211_vendor_event_brcm()`: `wpa_msg(NULL, MSG_INFO, "%s", data)` unconditional, `data` defaults NULL when netlink event omits `NL80211_ATTR_VENDOR_DATA`. | Malformed/short Broadcom vendor netlink event |
| 11 | `src/p2p/p2p.c` | 6308, 6313 | 6325, 6330 | `p2p_prepare_pasn_extra_ie()`: `p2p_encaps_ie()` can return NULL (OOM); dereferenced unguarded. | OOM during P2P PASN extra-IE prep |
| 12 | `src/utils/browser-android.c` | 38, 40, 43 | — | `http_req()`: `url = http_request_get_uri(req)` can be NULL; no `http_request_get_type()` check before `%s`/`os_strcmp`/`os_strncmp`. | HS2.0 OSU browser local loopback, malformed HTTP request line |
| 13 | `src/utils/browser-system.c` | 38, 40, 43 | — | Same as #12 (near-identical platform variant). | Same |
| 14 | `src/utils/browser-wpadebug.c` | 38, 40, 43 | — | Same as #12. | Same |
| 15 | `src/utils/http_curl.c` | 655 | — | `http_download_file()`: `ca_fname` passed unguarded to `wpa_printf`'s `%s`, despite being correctly guarded 2 lines later for its real use. | Optional CA-file config unset |
| 16 | `src/utils/trace.c` | 227 | — | `wpa_trace_bfd_addr()`: `filename` from libbfd can be NULL; guarded for trimming but not for the final `%s` log. | Debug build, symbol without filename info |
| 17 | `src/wps/http_client.c` | 215 | ~200 | `port = os_strchr(addr, ':')` NULL when URL has no colon; unguarded `%s` in `inet_aton` failure-path log. | Malformed WPS HTTP client URL |
| 18 | `wpa_supplicant/config_none.c` | 43 | 38 | `wpa_config_write()` (stub backend): `wpa_s->confname` NULL for a dynamically-added interface, unguarded `%s`, unlike `config_file.c` sibling. | `SET update_config 1` + `SAVE_CONFIG` on a no-`-c` interface |
| 19 | `wpa_supplicant/config_winreg.c` | 1019, 1024, 1058 | 1009, 1035, 1058 | Same root cause as #18, Windows registry backend: `name` also reaches `_snwprintf`/`os_snprintf` building the registry key path. | Same, Windows build |
| 20 | `wpa_supplicant/ctrl_iface.c` | 6596 | 6614 | `p2p_ctrl_connect()` PIN-keypad branch: `pos = os_strchr(pin, ' ')` NULL when no trailing params; falls through to unguarded `os_strstr(pos, ...)`. | `P2P_CONNECT <addr> <PIN>` local ctrl command, no trailing params |
| 21 | `wpa_supplicant/dbus/dbus_new_handlers_p2p.c` | 2308 | 2295 | `wpas_dbus_handler_remove_persistent_group`: `dbus_message_get_args()` return unchecked; `op` reaches unguarded `os_strncmp` in `dbus_new_helpers.c:984`. | Malformed/wrong-signature D-Bus method call |
| 22 | `wpa_supplicant/p2p_supplicant.c` | 1652 | — | `wpas_group_formation_completed()` → `wpas_notify_p2p_group_started()`: `ssid` NULL when not a P2P client; reaches `ssid->ssid` deref via `||` short-circuit in `dbus_new.c:1553`. | New-style D-Bus interface active, non-client P2P group start |
| 23 | `wpa_supplicant/wnm_sta.c` | 1223 | 1225 | `wnm_scan_process()`: `if (!bss) return 0;` guard scoped only to the `pre_scan_check` branch; post-scan path reaches unguarded `selected->bssid` deref in `events.c:2148` (now 2323). | Post-scan BTM candidate-selection path, no candidate found |

---

## Method (per finding)

1. `git -C ~/data-enterprise/hostap-main log --oneline <pin>..HEAD -- <file>` —
   many files had zero commits since the pin (definitive: unchanged); others
   had commits checked individually for relevance to the specific function.
2. Read the current trunk function body in full (not just the old line
   number — several shifted from unrelated additions earlier in the file).
3. Confirmed the same unguarded-pointer-reaches-unguarded-use shape is still
   present; none were narrowed to "fixed" or "refactored away."

No PoC/GDB reproduction was built for these (unlike the sqlite pair, which
warranted it specifically because the initial surprise was "already fixed" —
these needed only confirmation of currently-live status, not independent
crash proof beyond the original source reading).

## Re-verification against true `origin/main` (items 2, 4, 9, 20, 22, 23)

These 6 findings sit in the 6 files that changed further between the stale
local HEAD and the actual current trunk. Each was re-read directly from
`origin/main`'s content (`git show origin/main:<file>`), not just diff hunks
(a hunk's `@@` context line can name an unrelated nearby function and miss a
change deep inside a long one):

- **#2** (`hostapd_reconfig_wpa`) — unaffected; the file's diff activity was
  elsewhere. `hostapd_reconfig_wpa(hapd);` call site unchanged.
- **#4** (`wpa_auth_sta_deinit`) — unaffected; `wpa_get_primary_auth(wpa_auth)`
  still called unguarded at the same logical site (now line ~1244).
- **#9** (`eap_peap_build_phase2_term`) — the file's diff touched
  `eap_peap_process_phase2_soh` (the already-known/fixed SoH bug), not this
  function. Read in full on `origin/main`: `encr_req` still never NULL-checked
  before `wpabuf_resize(..., wpabuf_len(encr_req))` and `wpabuf_put_buf`.
- **#20** (`p2p_ctrl_connect`) — read in full: `if (pos) { *pos++ = '\0'; ... }`
  guards only the mutation, not the subsequent unconditional
  `os_strstr(pos, "bstrapmethod=")` — `pos` can still reach it NULL.
- **#22** (`wpas_group_formation_completed`) — unaffected; call site at line
  1652 on `origin/main` is unchanged.
- **#23** (`wnm_scan_process`) — most substantively re-checked: current trunk's
  control flow differs in shape from what was first read (a `#ifndef
  CONFIG_NO_ROAMING` roaming-rules block now sits between the `pre_scan_check`
  branch and a *second* `if (!bss)` guard). Traced it in full: the roaming-rules
  block's `wpa_supplicant_need_to_roam_within_ess(wpa_s, current_bss, bss, true)`
  call is reached with `bss` still possibly NULL (the second `if (!bss)` guard
  comes *after* it), and that function's body (`wpa_supplicant/events.c`)
  unconditionally does `wpa_bss_ie_ptr(selected)` / `selected->ie_len` as its
  first real statements, `selected` being the possibly-NULL `bss`. Still a live
  NULL deref, same defect, confirmed against `origin/main` line-by-line rather
  than assumed unchanged from the stale-HEAD reading.

All 6 confirmed still present. No conclusion in this document changed as a
result of the fetch/re-verify pass — recorded here for the record, not because
anything was wrong.
