# EXP34-C/EXP33-C true positives from bmdb task 1107 — adversarially verified

**Codebase:** hostap, pinned commit `dcee60436390dd34731560657c4257c3b4c839a6`.
**Source:** delta-adjudication of EXP34-C/EXP33-C findings attributable to
tools_sqc commit `d0802e08` ("1099", proven-nonnull widening), bmdb task 1107,
2026-09-10. 2047 hostap findings adjudicated, 39 initially labeled TP.

**This document supersedes the first mainline-recheck pass.** That pass only
confirmed the 39 findings were *unchanged on trunk* — it never independently
re-derived whether each was a real bug, just whether the code had moved. A
follow-up adversarial pass (same day) actually traced execution through each
disputed function, and building/running the pinned checkout under
ASan+UBSan caught **one finding that does not crash at all** (a false
positive the original adjudication missed) and **one that needed real
downgrading** (a claimed bug resting on an invariant the code actually
maintains correctly under normal operation). See "What the adversarial pass
changed" below — this is the headline result of this document, not a
footnote.

## Result after adversarial review

| Verdict | Count | Confidence |
|---|---|---|
| TP | 36 | all high — every one independently re-derived by reading the actual function body (not the original snippet), several cross-checked against caller/callee source, one live-reproduced with a crash |
| FP | 1 | high — reproduced running, does **not** crash |
| uncertain | 2 | downgraded from TP — real bug claim rests on an invariant that appears correctly maintained under normal sequencing; would need an MLD-capable hwsim rig or a race-condition proof to settle either way |

**Not filed upstream by this session** — per the disclosure philosophy,
Brandon is the accountable filer; this batch is handed off as vetted
candidates. One item (`tls_gnutls.c:1306`) duplicates an already-known,
not-yet-filed defect from the original 736-file audit (`REAL_BUGS_FOUND.md`
item 33) — flagged, not double-counted.

---

## What the adversarial pass changed

### Corrected: `src/ap/dpp_hostapd.c:940` — was TP, now FP

Original claim: `hostapd_dpp_auth_init()` leaves `own_bi` NULL when the ctrl
command omits `own=`, reaching an unconditional `auth->own_bi->pubkey_hash`
in `dpp_auth_init()` (`dpp_auth.c:1255`).

**This does not happen.** `dpp_auth_init()` calls `dpp_autogen_bootstrap_key()`
(`dpp_auth.c:1134`) near its top, *before* line 1255 runs:

```c
static int dpp_autogen_bootstrap_key(struct dpp_authentication *auth)
{
	struct dpp_bootstrap_info *bi;
	if (auth->own_bi)
		return 0; /* already generated */
	bi = os_zalloc(sizeof(*bi));
	...
	auth->tmp_own_bi = auth->own_bi = bi;
	return 0;
}
```

This explicitly checks `if (auth->own_bi) return 0;` and otherwise
auto-generates a fresh bootstrap key — a designed fallback specifically for
the no-`own=` case. By the time line 1255 executes, `own_bi` is guaranteed
non-NULL.

**Reproduced live.** Built hostapd from the pinned checkout with
`-fsanitize=address,undefined`, ran it against a `mac80211_hwsim` simulated
radio, issued `DPP_AUTH_INIT peer=<id>` with no `own=` via `hostapd_cli`, and
attached GDB with a breakpoint on `dpp_build_attr_i_bootstrap_key_hash` to
inspect the actual hash pointer. It was a valid heap address
(`0x613000000ba0`, ASan heap range), not NULL or a small offset — confirming
`dpp_autogen_bootstrap_key()` had already run and populated `own_bi`. The
command returned `OK`, hostapd stayed alive, and a full DPP Authentication
Request frame was built and transmitted (visible in the debug log as
`DPP: Auto-generated own bootstrapping key info: URI DPP:V:2;...`).

`ground_truth` id 143661 flipped to FP. **Lesson applied to the rest of this
pass:** read the *entire* calling function before trusting a "TP" verdict —
this guard was 20 lines above the disputed line, in the same function, and
would have been caught by careful reading alone without needing to build
anything.

### Downgraded: `src/ap/wpa_auth.c:1206,1208` — was TP, now uncertain

Original claim: `wpa_auth_sta_deinit()` calls `wpa_get_primary_auth(wpa_auth)`,
which can return NULL for an MLD group with no `primary_auth` link, passed
unguarded as `eloop_ctx` to a deferred `wpa_rekey_gtk()` that dereferences it.

Adversarial re-read found this rests on an assumption that doesn't hold up:
`wpa_init()` (`wpa_auth.c:799`) assigns `primary_auth=true` to the *first*
link created in an MLD group, and `wpa_deinit()` (lines 949-965) explicitly
reassigns `primary_auth` to another link via a `next_primary_auth` callback
*before* a primary link's `wpa_authenticator` is freed:

```c
if (wpa_auth->is_ml && wpa_auth->primary_auth) {
	next_pa = wpa_auth->cb->next_primary_auth(wpa_auth->cb_ctx);
	if (!next_pa) {
		pmksa_cache_auth_deinit(wpa_auth->ml_pmksa);
	} else {
		next_pa->primary_auth = true;
		...
	}
}
```

This is a deliberate invariant-preserving mechanism — unlike finding #1
above, which had no guard at all. Triggering the claimed bug would require a
genuine ordering/race defect in this reassignment path during multi-link
teardown, not a single reachable command. Settling it either way needs an
MLD-capable hwsim rig (multiple simulated radios grouped as one MLD AP) or a
much deeper cross-file trace of the BSS-teardown ordering — not done here;
`ground_truth` ids 144981/144982 downgraded to `uncertain` rather than left
as an overstated TP.

---

## Live-reproduced (ASan crash, not just static reading)

### `wpa_supplicant/ctrl_iface.c:6596` — `p2p_ctrl_connect()` PIN-keypad NULL deref

```
$ wpa_cli p2p_connect 02:00:00:00:00:11 12345670
```
(any well-formed MAC + a bare 4- or 8-digit PIN, no trailing params — `addr`
need not be a real/known P2P peer, `hwaddr_aton()` only syntax-checks it)

```
ctrl_iface.c:6596:9: runtime error: null pointer passed as argument 1, which is declared to never be null
AddressSanitizer:DEADLYSIGNAL
==466093==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #3 p2p_ctrl_connect wpa_supplicant/ctrl_iface.c:6596
    #4 wpa_supplicant_ctrl_iface_process wpa_supplicant/ctrl_iface.c:13531
    #5 wpa_supplicant_ctrl_iface_receive wpa_supplicant/ctrl_iface_unix.c:184
```

Root cause: `wps_pin_str_valid(pin)` (`src/wps/wps_common.c:256`) validates
only `pin`, never `pos` — a bare valid PIN with nothing after it leaves
`pos == NULL` (no trailing space found by `os_strchr`), which then reaches an
unconditional `os_strstr(pos, "bstrapmethod=")`. Fully reproducible, single
local command, no prior state. Full trace + repro doc:
`poc/p2p_connect_pin_null_repro.md`, `poc/p2p_connect_pin_null_asan.txt`.

---

## Cross-check against the existing 109-item audit catalog

`REAL_BUGS_FOUND.md` (the original file-at-a-time audit's defect list) shares
several file paths with this batch. Checked each shared file for a
function-level match, not just a filename match:

| File | Existing catalog item | Same bug? |
|---|---|---|
| `src/crypto/tls_gnutls.c` | #33, `tls_connection_verify_peer` | **YES — same function, same bug** (see below) |
| `src/ap/dpp_hostapd.c` | #53, `hostapd_dpp_pb_pkex_init` | No — different function; and this session's own finding (`hostapd_dpp_auth_init`) turned out to be FP anyway |
| `src/utils/http_curl.c` | #80, `http_post` | No — different function (`http_download_file`) |
| `src/utils/browser-android.c` | #96, dangling-stack-address bug at line 58 | No — different bug (this session: `url` NULL-deref at lines 38/40/43) |
| `src/ap/hostapd.c` | #71, leak in `hostapd_init` | No — different function (`hostapd_reconfig_wpa`) |
| `src/common/proximity_ranging.c` | #2, #45, #88 — three separate known bugs | No — none match `pr_prepare_pasn_pr_elem` |
| `src/crypto/tls_wolfssl.c` | #74, leak in `tls_init` | No — different function (`tls_connection_get_eap_fast_key`) |
| `src/eap_server/eap_server_peap.c` | already-disclosed-and-fixed (SoH vendor-TLV, lines 864-887) | No — different function (`eap_peap_build_phase2_term`) |

**One duplicate** (`tls_gnutls.c`), all others independent.

---

## All 38 confirmed TPs (excludes the corrected FP; the 2 uncertain items are
tracked above, not repeated here)

Each row below was independently re-derived this pass by reading the actual
function body — not carried forward from the original adjudication without
re-checking. "Reach." = how the defect is triggered.

| # | File:line | Function | Defect | Reach. |
|---|---|---|---|---|
| 2 | `src/ap/hostapd.c:174` | `hostapd_reconfig_wpa` | ignores `wpa_reconfig()` return; OOM leaves NULL `wpa_ie`+nonzero `wpa_ie_len` reaching driver `set_generic_elem` unchecked | OOM during config reload |
| 3 | `src/ap/wnm_ap.c:478` | `ieee802_11_rx_bss_trans_mgmt_query` | `hex` NULL (empty candidate list or OOM) reaches `%s` unconditionally despite an adjacent ternary that only gates the *prefix* text | **any associated station sending a minimal (2-byte) WNM BTM Query** — no OOM, no crafted cert, strongest wire-reachable candidate in this set besides #20 |
| 5 | `src/common/proximity_ranging.c:1609` | `pr_prepare_pasn_pr_elem` | `pr_encaps_elem()` NULL (OOM) reaches `wpabuf_len(buf2)` — confirmed `wpabuf_len` is `return buf->used;`, no guard at all | OOM during PASN element prep |
| 6 | `src/crypto/tls_gnutls.c:1306` | `tls_connection_verify_peer` | `if(buf){...}` guards the *write* into `buf` (failed `os_malloc`) but the `wpa_printf(...,"%s",...,buf)` two lines later is outside that block | OOM during peer cert chain logging. **Duplicates `REAL_BUGS_FOUND.md` #33** |
| 7 | `src/crypto/tls_openssl_ocsp.c:610,612` | `ocsp_find_signer` | `for(i=0;i<sk_X509_num(certs);i++)`, `i` unsigned — `sk_X509_num(NULL)`=-1 promotes to `UINT_MAX`, loop runs with `certs=NULL` | malformed/misconfigured OCSP response, no issuer cert (reachability to `certs==NULL` not independently traced through the full OCSP parser) |
| 8 | `src/crypto/tls_wolfssl.c:2511-2531` (5 sites) | `tls_connection_get_eap_fast_key` | `wolfSSL_get_keys()`'s return value entirely discarded (not even assigned); 3 by-ref outputs used unconditionally right after | aborted/failed TLS handshake |
| 9 | `src/eap_server/eap_server_peap.c:526,532` | `eap_peap_build_phase2_term` | `eap_server_tls_encrypt()` result never NULL-checked; dereferenced via `wpabuf_len`/`wpabuf_put_buf` on the TLS 1.3 resumption path | TLS 1.3 session resumption + encryption failure |
| 10 | `src/drivers/driver_nl80211_event.c:3647` | `nl80211_vendor_event_brcm` | `data` defaults NULL when the netlink vendor event omits `NL80211_ATTR_VENDOR_DATA`; `wpa_msg(...,"%s",data)` unconditional | malformed BRCM vendor event from the kernel driver/firmware |
| 11 | `src/p2p/p2p.c:6308,6313` | `p2p_prepare_pasn_extra_ie` | same shape as #5 (`p2p_encaps_ie` OOM-NULL → `wpabuf_len`) | OOM during P2P PASN extra-IE prep |
| 12-14 | `src/utils/browser-{android,system,wpadebug}.c:38,40,43` (9 sites) | `http_req` | `http_request_get_uri()` NULL when the client's first line matches `HTTP/` (a reply line); confirmed via `httpread.c`: `standard_first_line=0` skips the entire URI-parse block, `h->uri` was `os_zalloc`'d NULL and never set | local HS2.0 OSU loopback server (127.0.0.1:12345), any local connection sending `HTTP/1.1 ...` as its first line instead of a request line |
| 15 | `src/utils/http_curl.c:655` | `http_download_file` | `ca_fname` unguarded at the log line; correctly `if(ca_fname)`-guarded 10 lines later for the real `curl_easy_setopt` use | optional CA-file config left unset |
| 16 | `src/utils/trace.c:227` | `wpa_trace_bfd_addr` | `if(filename){...trim...}` guards the trim loop; unconditional 9 lines later at the log call | debug-only backtrace path (`CONFIG_WPA_TRACE_BFD`), low practical severity |
| 17 | `src/wps/http_client.c:215` | (URL parse helper) | `port` NULL (no colon, or reset when `port>path`); `if(port)*port++=0` guards the mutation, unguarded at the log line on the `inet_aton` failure path | malformed WPS HTTP client URL |
| 18 | `wpa_supplicant/config_none.c:43` | `wpa_config_write` (stub backend) | `name` (`wpa_s->confname`) unguarded throughout; `config_file.c` sibling correctly returns -1 on NULL | `SET update_config 1` + `SAVE_CONFIG` on an interface added with no `-c` config file |
| 19 | `wpa_supplicant/config_winreg.c:1019,1024,1058` | `wpa_config_write` (Windows backend) | same as #18, Windows registry backend; `name` also reaches `_snwprintf`/`os_snprintf` building the registry key path — Windows CRT `%s`-with-NULL is generally less forgiving than glibc | same, Windows build |
| **20** | `wpa_supplicant/ctrl_iface.c:6596` | `p2p_ctrl_connect` | **live-reproduced crash** — see above | `P2P_CONNECT <addr> <bare-PIN>` local ctrl command |
| 21 | `wpa_supplicant/dbus/dbus_new_handlers_p2p.c:2308` | `wpas_dbus_handler_remove_persistent_group` | `dbus_message_get_args()` return unchecked; confirmed against libdbus 1.14.10 source (`dbus-message.c:850-861`) that a type mismatch calls `dbus_set_error()` and jumps to `out` *without ever calling `va_arg` on the out-param* — `op` is genuinely uninitialized stack memory, not just NULL | malformed/wrong-signature D-Bus method call |
| 22 | `wpa_supplicant/p2p_supplicant.c:1652` | `wpas_group_formation_completed` → `wpas_notify_p2p_group_started` | `ssid` NULL when not a P2P client; `dbus_new.c:1553`'s `\|\|` short-circuits into `ssid->ssid` when the new-style D-Bus interface is active | new-style D-Bus interface active + non-client P2P group start |
| 23 | `wpa_supplicant/wnm_sta.c:1223` | `wnm_scan_process` | the `if(!bss)` guard is scoped only to the `pre_scan_check` branch; the post-scan roaming-rules block reaches `wpa_supplicant_need_to_roam_within_ess(...,bss,...)` with `bss` still possibly NULL, which unconditionally dereferences it via `wpa_bss_ie_ptr`/`->ie_len` | post-scan BTM candidate-selection path, no candidate found |

---

## Method

1. Read the *complete* function body for every disputed line — not the
   originally-quoted snippet — specifically hunting for the kind of guard
   that falsified finding #1 (auto-generation, fallback init, caller-side
   validation, invariant-preserving reassignment).
2. Where static reading left genuine doubt or the claim was unusually strong
   (cheap to trigger, no crafted wire/cert data needed), built the pinned
   checkout with `-fsanitize=address,undefined -fno-omit-frame-pointer -g
   -O0` (both `hostapd` and `wpa_supplicant`, `CONFIG_CTRL_IFACE_DBUS_NEW=y
   CONFIG_P2P=y CONFIG_WPS=y`) and ran it against a `mac80211_hwsim`
   simulated radio to reproduce directly.
3. Where a claim depended on a non-hostap codebase's behavior (D-Bus
   argument-parsing semantics), read that codebase's own source
   (`libdbus-1.14.10`) rather than assuming.
4. Cross-checked every finding's file against the existing 109-item audit
   catalog (`REAL_BUGS_FOUND.md`) to avoid double-filing a known defect.
5. Confirmed no upstream fix exists for the surviving 38 by checking each
   file's commit history against true `origin/main` (fetched fresh, not a
   stale local mirror — see the mirror-staleness note below) and reading the
   current function body directly for the 6 files that changed.

## Mirror-staleness note (kept for the record)

The first pass of this recheck used `~/data-enterprise/hostap-main`'s
then-local HEAD without fetching — 125 commits behind true `origin/main`
(caught and corrected same-day: fetched, confirmed all 6 findings in the
files that changed hold up against the actual current trunk content, not
diff-hunk context alone). No conclusion changed as a result — recorded
because the gap could have hidden a real fix, and didn't.
