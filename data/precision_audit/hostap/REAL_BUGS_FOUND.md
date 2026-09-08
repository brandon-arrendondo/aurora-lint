# hostap Ground-Truth Audit — Real Defect Bug List

**Codebase:** hostap (hostapd + wpa_supplicant), commit `dcee60436390dd34731560657c4257c3b4c839a6`
**Scope:** 736 files, 337 adjudication batches, ~33,330 labeled sqc findings (precision-audit ground-truth build). This report is a side-effect of that adjudication: while reviewers labeled each sqc finding TP/FP, they also did full file read-throughs and logged genuine hostap defects sqc's rule set missed (or, in a few flagged cases, correctly caught). Below is every such defect extracted from the 33-wave audit log, **excluding** sqc rule-engine bugs/FP-pattern discussion (a separate, larger category in the source notes). None of these have been reported to hostap upstream yet.

**Status: verified against current hostap mainline as of 2026-08-25** (task 399, step 1). See `MAINLINE_TRIAGE_TASK399.md` in this directory for the per-item still-present/already-fixed/changed breakdown. Everything below is still pinned to the ORIGINAL commit `dcee60436` and has NOT been edited in place — always cross-reference the triage file's current-location column before citing a line number from this report.

**2026-09-08: Section 1 items 1, 4, 5, 6, 7, 9, 14, 16 were disclosed privately to Jouni Malinen (2026-08-25) and fixed upstream by him on 2026-09-08** (no separate security advisory published — impact judged too small, and he doubts practical reachability of items 1, 14 and 16 specifically). Item 15 (also section 1) was found already fixed *before* our filing, per w1.fi advisory 2026-3. See `MAINLINE_TRIAGE_TASK399.md`'s Section 1 table for the fixing commits and todo-sqlite-cli tasks 587/588 for the full response and disposition. Items 12 and 13 remain open but were never filed (judged not reachable).

---

## 1. Attacker-reachable / wire-data memory-safety bugs (highest priority)

These are triggered by data received from the network (a peer AP, station, or protocol frame) — the most severe class for upstream disclosure.

| # | File:Line | Wave/Batch | Defect | Class | Confidence | Reachability |
|---|---|---|---|---|---|---|
| 1 | `src/ap/wpa_auth_ft.c` ~2419 (`wpa_ft_process_rdie`) | W11/b72 | Bounds-checks `sizeof(*rdie)` but then writes 2 extra header bytes beyond that check. | Overflow (OOB write, off-by-2) | High | Attacker-controlled 802.11r FT RIC subelement data from an associating station |
| 2 | `src/common/proximity_ranging.c:941` (`pr_process_channels`) | W23/b186 | Writes into a fixed 15-element `op_class[]` array bounded only by attacker-controlled wire byte `op_class_count` (0-255), never checked against `PR_MAX_OP_CLASSES`; sibling `pr_channels_intersect()` bounds-checks correctly. | OOB write (up to 60 attacker bytes/entry) | High | Unauthenticated USD frames + PASN Auth1/2/3 |
| 3 | `wpa_supplicant/events.c` (`wpas_ml_parse_assoc`) | W13/b85 | Only lower-bound-checks `common_info->len` before subtracting from `size_t ml_len` → unsigned underflow. | OOB read | High | Malicious/corrupted AP's EHT Multi-Link element in an Association Response |
| 4 | `src/common/ieee802_11_common.c` part1 (`get_max_nss_capability`) | W13/b93 | Reads `hecaps->optional[0..7]` without validating `elems->he_capabilities_len` against the field's length requirement. | OOB read (4-8 bytes) | High | Malicious AP's HE Capabilities element |
| 5 | `src/ap/ieee802_11_eht.c` (`hostapd_parse_link_reconf_req_sta_profile`) | W21/b184-ish | OOB read when `sta_info==end`, a valid boundary case under the only preceding length check. | OOB read (ARR30-C class) | Medium-High | Attacker-controlled Multi-Link Reconfiguration wire data |
| 6 | `src/common/ieee802_11_he.c:478` (`copy_sta_he_capab`) | W31/b265-274 | Calls `check_valid_he_mcs()` (reads `sta_mcs_set[i*4]`, no length param) **before** the IE-length validation call. | OOB read | High | Malformed/short HE-Capabilities IE from a station |
| 7 | `src/ap/drv_callbacks.c` (`hostapd_action_rx`, CONFIG_NAN_USD branch) | W22/b175 | Checks only `plen>=5` before reading byte offset 5 (needs `>=6`); sibling CONFIG_DPP branch does this correctly. | OOB read (1 byte + cascading ptr arithmetic) | High | Untrusted peer's 5-byte NAN public-action frame |
| 8 | `wpa_supplicant/tdls.c:1000` (`wpa_tdls_recv_teardown`) | W24/b195-204 | Reads a 2-byte reason code 5 bytes into the frame with no length check; dispatcher only guarantees 3 bytes. Sibling `tpk_m2`/`tpk_m3` guard the identical idiom. | OOB read (INT30-C class) | High | Short attacker-sent TDLS Teardown frames |
| 9 | `src/eap_server/eap_server_peap.c:864-887` (SoH vendor-TLV) | W31/b265-274 | Checks `tlv_len<4` but reads a 4-byte header at `pos+4`; needs `tlv_len>=8`. | OOB read (small) | Medium | Attacker wire data |
| 10 | `wpa_supplicant/p2p_supplicant_sd.c:604` (`wpas_sd_req_asp`) | W27/b225-234 | For a prefix (`*`-suffixed) ASP service query, the length-mismatch guard is skipped, so `os_memcmp(svc_name, svc, svc_len)` reads attacker-controlled `svc_len` (up to 254) against a possibly-shorter local heap string. | OOB heap read (ARR38-C class) | Medium | Crafted P2P Service Discovery Request |
| 11 | `src/radius/radius_client.c` (`radius_msg_verify_das_req`, `radius_msg_verify_msg_auth`) | W20/b155-164 | Each `os_memcpy`s a fixed 16 bytes from the wire-derived Message-Authenticator attribute without validating `attr->length` first. | OOB read | High | RADIUS server's wire response |
| 12 | `src/eap_server/eap_server.c:620` (`SM_STATE(EAP,NAK)`) | W26/b215-224 — **sqc caught this correctly (TP, not a miss)** | `len -= sizeof(*nak)` has no preceding check that attacker-controlled EAP-Response/Nak length is `>= sizeof(*nak)`; underflows to huge `size_t`, flows into `wpa_hexdump()` and an unbounded loop bound. | Unsigned underflow → OOB read | High | Remote, unauthenticated peer's EAP-Response/Nak reaching hostapd (authenticator side) |
| 13 | `src/common/nan_de.c:1313` (`nan_check_bloom_filter`) | W27/b225-234 — **sqc caught this correctly (TP)** | Unguarded `crc %= bf_len * 8` reachable with `bf_len==0` via a 1-byte attacker-controlled SRF-filter length. Sibling `bloom_filter_add` is safe because its call site gates on nonzero length. | Mod-by-zero crash (remote DoS) | High | Received NAN Service Discovery Frame, unauthenticated |
| 14 | `src/common/nan_de.c:651` (`nan_de_config`) | W27/b225-234 | Only rejects `n_max<n_min`, not `n_max==n_min`; equal values later cause mod-by-zero in `nan_de_start_new_publish_state`. | Mod-by-zero (INT33-C) | Medium | NAN config path with equal bounds |
| 15 | `src/common/sae.c` (`sae_parse_token_container`) | W18/b135-144 — **sqc caught this correctly (TP, EXP34-C)** | No NULL guard on `token`/`token_len` (unlike sibling `sae_parse_commit_token()`); `pasn_responder.c`/`pasn_initiator.c`/`sme.c` call `sae_parse_commit()` with `h2e` forced true and `token=token_len=NULL`. | NULL-deref DoS | High | Unauthenticated peer via PASN |
| 16 | `src/eap_server/eap_server_ttls.c:1224` (resumption path) | W31/b265-274 | Checks `len<1` but reads 2nd byte; needs `<2`. | Off-by-one over-read | Medium (currently unreachable — writer always emits ≥2 bytes) | Wire data, latent |

---

## 2. Other reachable memory-safety / crypto-integrity bugs (local IPC, privsep, config, or driver-specific)

| # | File:Line | Wave/Batch | Defect | Class | Confidence | Reachability |
|---|---|---|---|---|---|---|
| 17 | `wpa_supplicant/dbus/dbus_new_handlers.c:3192` (`wpas_dbus_handler_set_pkcs11_engine_and_module_path`) | W6/b28 | `os_free()` on a pointer that aliases the D-Bus message's own internal string buffer rather than allocated memory. | Invalid free | High | Crafted D-Bus method call, missing 2nd arg after a valid 1st |
| 18 | `hostapd/ctrl_iface.c:2219` (`hostapd_ctrl_set_key`) | W7/b37 (CONFIG_TESTING_OPTIONS build) | `key_len` computed from unbounded user-supplied hex string, passed to `hexstr2bin()` writing into a fixed 32-byte stack buffer (`u8 key[WPA_TK_MAX_LEN]`) with no upper-bound check. | Stack buffer overflow | High | Local control interface, test-build only |
| 19 | `wpa_priv.c` (`wpa_priv_cmd_authenticate`/`wpa_priv_cmd_associate`) | W21/b165-174 | Length checks of form `sizeof(*hdr)+hdr->attacker_controlled_len > len` can integer-overflow, bypassing validation. | Integer overflow → validation bypass | Medium-High | Any local user (privsep control socket is chmod 0777) |
| 20 | `wpa_supplicant/proc_coord.c:375` | W31/b265-274 | `os_memcpy(tmp[20], pos, end-pos)` from peer-controlled `sockaddr_un.sun_path`, no bounds check vs `sizeof(tmp)`; unterminated before `atoi()`. | Stack buffer overflow | Medium-High | Same-host peer |
| 21 | `src/l2_packet/l2_packet_privsep.c:71` (`l2_packet_send`) | W31/b265-274 | `io[1].iov_base = &dst_addr` (address of the pointer param itself) instead of `(u8*)dst_addr` (the 6-byte MAC). | Stack-data disclosure / garbage dest addr | Medium | CONFIG_PRIVSEP, local IPC to privileged helper |
| 22 | `src/common/sae_pk.c` | W25/b205-214 | `sae_pk_set_password` never caps local SAE-PK password length before deriving fingerprint bits; `tmp->fingerprint[SAE_MAX_HASH_LEN=64]` can overflow via unbounded `*pos++=` writes. | Stack/heap overflow | Medium | Local config, long SAE-PK password string |
| 23 | `src/drivers/driver_ndis.c` (`wpa_driver_ndis_get_names`, `wpa_driver_ndis_get_interfaces`, `ndisuio_notification_receive`) | W17/b127/b128 | 3 heap over-read/overflow bugs in UNICODE-adapter-name conversion loops + 1 unvalidated offset/size. | Heap over-read/overflow | Medium (legacy Windows NDIS/WZC backend, upstream_present unknown) | Local Windows driver interaction |
| 24 | `src/drivers/driver_bsd.c` (`bsd_set_ssid`, scan-result parse loop) | W20/b155-164 | Unbounded/unchecked `sr->isr_len` driver-reported length arithmetic; unbounded `os_memcpy` into `nwid.i_nwid` sized by caller `ssid_len`. | Overflow/over-read | Low-Medium | Driver-reported data (BSD wireless ioctl) |
| 25 | `src/rsn_supp/wpa.c`/NDIS event backend `ndis_events.c` | W21/b165-174 | Unchecked `SafeArrayGetLBound/UBound` HRESULTs can drive an uninitialized-length malloc + OOB copy loop from untrusted NDIS data. | OOB copy | Medium (Windows) | Untrusted NDIS event data |
| 26 | `src/crypto/crypto_libtomcrypt.c` (`aes_decrypt`) | W23/b185-194 | Calls `aes_ecb_encrypt()` instead of an ECB-decrypt primitive (identical body to `aes_encrypt()`, args swapped, const cast away) — re-encrypts instead of decrypting. | Crypto correctness bug | High (but backend rarely built — CONFIG_INTERNAL_LIBTOMCRYPT, likely dormant) | N/A |
| 27 | `hostapd/main.c` / `wpa_supplicant.c:7638`-adjacent `driver_wired.c` fd leaks | W31/b265-274 | 6 additional fd leaks in `wired_init_sockets()` failure paths (same no-cleanup-path family sqc did catch elsewhere in the same function). | fd leak | Medium | Interface init failure |

---

## 3. NULL-dereference bugs

| # | File:Line | Wave/Batch | Defect | Confidence | Reachability |
|---|---|---|---|---|---|
| 28 | `wpa_supplicant/dbus/dbus_new_handlers.c:4961/4991/5021` (`wpas_dbus_getter_sta_address/_aid/_caps`) | W6/b30 | Dereference `args->wpa_s->ap_iface->bss[0]` with no NULL guard, while 4 sibling getters in the same file guard `ap_iface` first. | Plausible | Local D-Bus getter call |
| 29 | `wpa_supplicant/dbus/dbus_new_handlers.c:*` (`wpas_dbus_handler_nan_subscribe`) | W7/b31 | Unchecked NULL after `dbus_message_new_method_return`, unlike sibling `nan_publish`. | Medium | OOM |
| 30 | `src/pae/ieee802_1x_kay.c` (`ieee802_1x_kay_create_mka`) | W15/b112 | `kay->if_name` dereferenced in an opening `wpa_printf` 2 lines before the NULL check on `kay`. | Low (no caller currently passes NULL) | Latent |
| 31 | `src/wps/wps_er.c` (`wps_er_get_sta_uuid`) | W23/b185-194 | Called from `wpas_wps_er_add_pin()` with no NULL check on `wpa_s->wps_er`. | Medium | WPS_ER_PIN ctrl_iface command issued before WPS_ER_START |
| 32 | `src/ap/rrm.c` (`wpas_rrm_send_neighbor_rep_request`) | W23/b185-194 | Stores caller-supplied `cb` callback with no NULL-check despite its own doc comment implying one is required. | Medium | — |
| 33 | `src/tls/tls_gnutls.c` (`tls_connection_verify_peer`) | W21/b165-174 | `%s`-format with NULL arg on malloc failure. | Medium | OOM |
| 34 | `src/wps/wps_upnp_event.c:133` (`event_addr_failure`) | W33/6-15_b7-11+16-40_b25-34 | NULLs `e->addr` then calls `event_retry(e,0)`, which can reach a branch dereferencing the now-NULL `e->addr->domain_and_port`. | Medium | Reachable with 2 addresses, higher-indexed one deleted |
| 35 | `src/dbus/dbus_new_helpers.c:177-178` (`properties_get`) | W26/b215-224 | Never NULL-checks `dbus_message_new_method_return(message)` before dereferencing it; sibling `get_all_properties()` guards the identical call. | Medium | OOM, local D-Bus |
| 36 | `src/eap_peer/eap_teap.c:1387` | W31/b265-274 | `config=eap_get_config(sm)` dereferenced with no NULL check while every sibling call site guards it. | Medium | — |
| 37 | `src/tls/tls_openssl.c` (`tls_match_altsubject_component`) | Mini-wave/b44 | Possible EXP34-C null-deref on attacker-supplied cert data. | Medium-Low | Attacker-controlled certificate data |
| 38 | `src/eap_peer/eap_aka.c` | W28/b235-244 | Unchecked `os_memdup()` result stored into `data->mk_identity` at 4 sites while `mk_identity_len` set unconditionally; on OOM feeds NULL pointer with nonzero length into `sha1_vector`/`sha256_vector`. | Medium | OOM only |
| 39 | `src/eap_peer/eap_server_sim.c` | W28/b235-244 | `eap_sim_msg_init()`'s return never NULL-checked across 4 message-builder functions. | Medium | OOM only |
| 40 | `src/utils/os_win32.c` (`os_rel2abs_path`) | W28/b235-244 | No NULL guard (unlike `os_unix.c` sibling); `wpa_supplicant.c:7734` calls it with `iface->confanother`, genuinely unguarded at that call site. | Medium | Windows config path |
| 41 | `src/xml/xml_libxml2.c:39` (`xml_node_from_buf`) | W28/b235-244 | Never NULL-checks `xmlDocGetRootElement(doc)` before `xmlCopyNode()` — the function parsing externally-sourced XML (OSU/Hotspot2 profiles). | Low-Medium | OSU/Hotspot2 provisioning XML |
| 42 | `src/utils/os_unix.c` (`os_exec`) | W19/b145-154 | Potential `os_strlen(NULL)` NULL-deref if a caller passes `arg==NULL`; also two unchecked `os_strdup()` results feed `execv()`'s `argv[0]`. | Medium | — |

---

## 4. Double-free / UAF

| # | File:Line | Wave/Batch | Defect | Confidence |
|---|---|---|---|---|
| 43 | `wpa_supplicant/eapol_test.c` (`test_eapol`) | W17/b125-134 | Frees `ctx` via `os_free()` after `eapol_sm_init(ctx)` already succeeded and `wctx` alloc fails — frees memory now owned by the live `wpa_s->eapol` object. Latent double-free if `eapol_sm_deinit()` is later reached. | Medium-High |

---

## 5. Broken error contracts / logic bugs

| # | File:Line | Wave/Batch | Defect | Confidence |
|---|---|---|---|---|
| 44 | `src/crypto/crypto_wolfssl.c` (`read_rsa_key_from_x509`) | W13/b87/b88 (confirmed twice) | Leaves `*key_der` non-NULL after a failed `wc_GetPubKeyDerFromCert()` call following successful `wc_AllocDer()` — caller's NULL-check doesn't catch the failure; unpopulated DER buffer passed to the RSA decoder. | Medium |
| 45 | `src/common/proximity_ranging.c` (`pr_pasn_handle_auth_3`) | W23/b185-194 | No-final-else on `protocol_type` switch is security-relevant: unmatched value bypasses channel/role validation, letting unvalidated peer data flow into `dev->final_op_channel`/`final_op_class`. | High |
| 46 | `src/eap_server/eap_server_fast.c:713` (`eap_fast_build_pac`) | W26/b215-224 | Truncates `size_t identity_len` to a single byte (`*pos++ = sm->identity_len`) for the PAC-Opaque Identity TLV — wire-format correctness bug for identities >255 bytes. | High |
| 47 | `wpa_supplicant/ctrl_iface_udp.c` | W27/b225-234 | `inet_ntop()` size arg passed as `sizeof(*from)`/`sizeof(from)` (source struct, ~28B) instead of `sizeof(addr)` (dest buffer, 46B), 5x. Understates size (safe direction) but a real logic bug. | Medium |
| 48 | `src/utils/os_internal.c` (`os_exec`) | W20/b155-164 | Forked child calls `exit(0)` after `execv()` itself fails, masking failure from `waitpid()`-based caller. | Medium |
| 49 | `src/utils/eloop.c:376-377` (`eloop_sock_table_add_sock`) | W28/b235-244 | Doesn't roll back `table->count`/`eloop.count` if the `epoll_ctl`/`kevent` ADD syscall fails after the socket entry was already appended — leaves phantom registered-but-non-functional sockets. | Medium |
| 50 | `wpa_supplicant/hostapd_cli.c` (`hostapd_cli_cmd_wps_config`) | W12/b83 | Checks `argc<1` but needs `argc>=2`; `argc==1` falls through to `argv[1]`, an out-of-bounds NULL-sentinel read used as a `%s` vararg. | High |
| 51 | `wpa_supplicant/p2p_supplicant_sd.c:429` (`wpas_sd_req_upnp`) | W27/b225-234 | Leaves a committed-but-unfilled TLV length field in the shared response buffer if `os_malloc` fails. | Low-Medium |
| 52 | `src/common/dpp_tcp.c` (`dpp_controller_rx_gas_req`) | W18/b135-144 | Passes the wrong length variable (`len` instead of `e_len`) to `printf_encode()` as `maxlen`. Currently non-exploitable. | Medium |
| 53 | `wpa_supplicant/dpp_hostapd.c` (`hostapd_dpp_pb_pkex_init`) | W18/b135-144 | Missing else between an if/else-if chain; harmless today only because `conf_id` is hardcoded -1. | Low |
| 54 | `hostapd/config_file.c` (ANQP domain-name length-prefix) | W6/b24 | Truncation desync (INT31-C-shaped). | Medium, config-only |
| 55 | `wpa_supplicant/bgscan_learn.c` | W31/b265-274 | `signal_threshold=atoi(pos)` has zero downstream validation/clamp unlike sibling `short_interval`/`long_interval`. | Low |

---

## 6. Memory-write / OOB-write bugs (config- or admin-triggered, not remote wire)

| # | File:Line | Wave/Batch | Defect | Confidence |
|---|---|---|---|---|
| 56 | `hostapd/config_file.c:1272` (`hostapd_parse_he_srg_bitmap`) | W5/b20 | `bitpos>64` should be `>63` against an 8-byte bitmap array — 1-byte OOB write. | High. Reachable via `he_spr_srg_bss_colors`/`he_spr_srg_partial_bssid` config directives (admin-config only) |
| 57 | `src/fst/fst_ctrl_iface.c` (`list_session_enum_cb`) | W18/b135-144 | Uses `os_snprintf`'s return value unguarded to advance/decrement `c->buf`/`c->buflen`; no `os_snprintf_error()` check unlike sibling loops — truncation/error underflows `buflen`, enabling OOB write on next iteration. | Medium-High |
| 58 | `src/utils/json.c:53` (`json_escape_string`) | W24/b195-204 | Unchecked `os_snprintf` return advances `txt` past end when a `\uXXXX` escape truncates with 5-6 bytes remaining; trailing `txt='\0'` writes out of bounds. | Medium |
| 59 | `src/radius/radius_client.c:2079` (`radius_client_get_mib`) | W24/b195-204 | Accumulates `os_snprintf()` returns without checking `buflen`; if exceeded, `buflen-count` underflows and walks past buffer end. Needs many configured RADIUS servers. | Medium |
| 60 | `wpa_supplicant/wpa_helpers.c:78` (`wpa_command_resp`) | W27/b225-234 | Unguarded `resp[len]='\0'` off-by-one overflow (sibling function explicitly guards it). Reachable transitively via `add_network`/`add_cred`. | Medium-High |
| 61 | `wpa_supplicant/wpa_helpers.c:52,181` (`wpa_command`/`get_wpa_status`) — **sqc caught this correctly (TP)** | W27/b225-234 | Null-terminate at `buf[len]` where `len` can equal the buffer's full capacity via `wpa_ctrl_request`'s unguarded return path. | Confirmed TP |
| 62 | `src/utils/common.c` (`wpa_snprintf_hex_sep`) — **sqc caught this correctly (TP)** | W16/b115-124 | Off-by-one buffer underwrite (writes `pos[-1]` before `buf` when `len==0`); currently unreached in practice. | Confirmed TP |

---

## 7. Sensitive-data hygiene (key/secret zeroization)

| # | File:Line | Wave/Batch | Defect |
|---|---|---|---|
| 63 | `src/crypto/crypto_openssl.c` (`crypto_ec_key_debug_print`) | W7/b33 | Frees rendered EC private-key material via plain `os_free()` without clearing first. |
| 64 | `src/common/dpp_crypto.c` (`dpp_derive_auth_i`) | W19/b145-154 | Returns -1 directly instead of `goto fail` on failed `dpp_hkdf_expand`, skipping `forced_memzero()` on `Sx`/`tmp` — leaves ECDH shared secret + HKDF intermediate key material un-zeroed on the stack. |
| 65 | `wpa_supplicant/dpp_backup.c` | W30/b255-264 | Derived password material (`key[DPP_MAX_HASH_LEN]`) never `forced_memzero()`'d, unlike sibling `kek` buffers. |
| 66 | `src/eap_peer/eap.c` (`eap_get_ext_password`) | W20/b155-164 | Plaintext password heap buffer freed with plain `os_free()` instead of a clearing free. |

---

## 8. Signal-handler safety

| # | File:Line | Wave/Batch | Defect |
|---|---|---|---|
| 67 | `hostapd/hlr_auc_gw.c` (`handle_term`) | W14/b99, b100 (reconfirmed) | SIGTERM/SIGINT handler calls `cleanup()` → `printf`/`fclose`/`sqlite3_close`/`unlink`/`close`/malloc-family — none async-signal-safe. SIG30-C violation. |

---

## 9. Resource / memory leaks (non-security-critical unless noted)

| # | File:Line | Wave/Batch | Defect |
|---|---|---|---|
| 68 | `wpa_supplicant/dbus/dbus_new_handlers.c:1425/1491/1594` (`wpas_dbus_handler_scan`) | W6/b27 | A `Scan()` D-Bus call with duplicate SSIDs/IEs/Channels dict keys silently overwrites `params->{ssids,extra_ies,freqs}` without freeing prior allocation. Attacker(local D-Bus caller)-reachable. |
| 69 | `src/drivers/driver_nl80211.c` (`wpa_driver_nl80211_if_add` error paths) | W5/b15 | 2 real leaks in error paths. |
| 70 | `hostapd/hlr_auc_gw.c` (`main`, error paths) | W14/b100, b99 | Leaks `sqlite_db` on `open_socket` failure path (before `atexit(cleanup)` registered); three early-return error paths leak already-linked `gsm_db`/`milenage_db` list nodes + the open sqlite_db handle. |
| 71 | `src/ap/hostapd.c` (`hostapd_init`) | W15/b107 | Leaks already-allocated `hapd_iface->bss[0..i-1]` entries if a later `hostapd_alloc_bss_data()` call fails mid-loop; sibling `hostapd_data_alloc()` handles this correctly. |
| 72 | `src/pae/ieee802_1x_kay.c` (`ieee802_1x_participant_send_mkpdu`) | W15/b111 | Leaks a `wpabuf_alloc`'d buf when `ieee802_1x_kay_encode_mkpdu()` fails and returns -1 without freeing it. |
| 73 | `wpa_supplicant/ap.c` (`wpas_ap_pmksa_cache_add_external`) | W16/b118 | OOM-only leak of a pmksa_cache entry if the subsequent entry allocation fails. |
| 74 | `src/tls/tls_wolfssl.c` (`tls_init`) | W17/b133 | Leaks the freshly-allocated `tls_context` and orphans `tls_global` if `wolfSSL_Init()` fails on the very first init call. |
| 75 | `src/ap/beacon.c` | W18/b137 | 3 early returns inside a CONFIG_SAE offload block leak `head`/`tail`/`resp`; also a narrower leak of `link_params.resp` in `hostapd_gen_per_sta_profiles`. |
| 76 | `src/crypto/crypto_linux.c` (`aes_unwrap`) | W20/b155-164 | skcipher context (2 fds + heap struct) leaked on `sendmsg()` failure path; sibling `read()`-failure branches correctly free it. |
| 77 | `wpa_supplicant/driver_privsep.c:548` (`wpa_driver_privsep_receive`) | W25/b205-214 | "Too short event message" branch leaks the 2000-byte `os_malloc()`'d buffer; sibling error branch two lines above frees it correctly. |
| 78 | `src/common/dpp_pkex.c` (`dpp_pkex_finish`) | W26/b215-224 | Leaks the whole pkex object when `dpp_bootstrap_key_hash(bi)` fails — frees only `bi`, never `dpp_pkex_free(pkex)`. |
| 79 | `src/ap/wpa_auth_glue.c` (`hostapd_wpa_register_ft_oui`) | W26/b215-224 | Leaks earlier-registered `eth_p_oui` handles if a later registration fails; config-reload caller ignores the return value. |
| 80 | `http/http_curl.c:708` (`http_post`) | W24/b195-204 | Leaks CURL easy handle + `curl_slist` header list on every call (no cleanup on any path); sibling `http_download_file()` cleans up correctly. |
| 81 | `src/tncc/tncc.c:1086-1089` (`tncc_read_config`) | W26/b215-224 | Line-splitting loop's `line_end < end` check placed last in an `&&` chain — dereferences one byte past a non-NUL-terminated buffer; also causes an OOB write via `*line_end='\0'`. Local config file. |
| 82 | `wpa_supplicant/main.c` (`hostapd_cli.c` main) | W12/b84 | Two early failure returns (action_file/daemonize) skip tail cleanup path every other exit runs. |
| 83 | `hostapd/main.c:913` (getopt cases 'g'/'G'/'u') | W24/b195-204 | Return directly instead of `goto out;`, leaking `interfaces.dpp` (and any already-set pid_file). |
| 84 | `src/mesh/mesh_rsn.c:285` (`mesh_rsn_auth_init`) | W30/b255-264 | Leaks the heap-allocated mesh_rsn context if `wpa_auth_pmksa_add_entry()` fails inside the PMKSA-cache restore loop. |
| 85 | `wpa_supplicant/xml-utils.c` (`get_val`) | W30/b255-264 | Leaks heap string from `xml_node_get_text()` when the XML text node is entirely whitespace. |
| 86 | `src/drivers/driver_macsec_qca.c` (`macsec_qca_init_sockets`) | W22/b175-184 | Leaks raw packet socket fd + eloop registration on 5 separate error-return branches. |
| 87 | `src/drivers/driver_macsec_linux.c` (`macsec_drv_init_sockets`) | W23/b185-194 | Same fd-leak class (3rd confirmed instance). |
| 88 | `src/common/proximity_ranging.c` (`pr_process_pasn_ranging_wrapper`) | W23/b185-194 | Leaks buf on an early return -1 (currently unreachable). |
| 89 | `src/utils/module_tests/common_module_tests.c` (`sae_tests`) | W22/b175-184 | FFC branch calls `sae_deinit_pt(pt)` on a mid-list node instead of the list head, leaking every earlier PT node. |
| 90 | Windows: `main_winsvc.c`, `eloop_win.c` | W30/b255-264 | `kill_svc` HANDLE leak on `CreateThread` failure (main_winsvc.c); `eloop_destroy()` frees the readers array without closing each entry's WSAEVENT handle first (eloop_win.c). |
| 91 | `src/l2_packet/l2_packet_pcap.c` (`l2_packet_init`) | W32 | Leaks the pcap/BPF fd if `l2_packet_init_libpcap()` fails after `pcap_open_live()` already succeeded; nested `pcap_compile()`'s `bpf_program` also leaked if `pcap_setfilter()` fails. |
| 92 | `src/ap/robust_av.c` (`populate_type10_classifier_data`) | W32 | On an `os_memdup()` OOM failure mid-loop, unprocessed array elements hold shallow-copied pointers aliasing the source list's own allocations; both callers then free the whole destination array on error, double-freeing memory still owned by the source list entry. |
| 93 | `src/drivers/driver_wired.c` (`wired_init_sockets`) | W31/b265-274 | 6 additional fd leaks in failure paths (see item 27, same family). |

---

## 10. Lower-severity / miscellaneous (config-only, dead code, unreachable-in-practice, out-of-scope backends)

| # | File:Line | Wave/Batch | Defect |
|---|---|---|---|
| 94 | `src/wps/wpa_passphrase.c:58` | W33 | Reads-then-writes an uninitialized `struct termios` on the ENOTTY goto path; value never subsequently used. |
| 95 | `src/eap_peer/eap_teap_common.c` area | W33 | FN carried from a b11 batch summary, no exact line preserved in the notes (result JSON has detail). |
| 96 | Android: `browser-android.c:58` | W33 | Passes `&data` (address of a local pointer, not the struct) into `eloop_register_timeout()` — latent dangling-stack-address escape, currently harmless (callback ignores params). |
| 97 | `src/drivers/driver_openbsd.c` (`wpa_driver_openbsd_set_key`) — sqc caught this correctly (TP, MSC37-C/MSC07-C) | W33 | Missing closing brace after `return -1;` swallows the rest of the function into dead code. |
| 98 | `wpa_supplicant/p2p/p2p_pd.c` | W20/b155-164 | `os_malloc(2*info_len+1)` with no upper-bound check on attacker-influenced `session_info_len` before doubling — low severity, frame-size bounded. |
| 99 | `src/utils/os_win32.c` (`os_readfile`) | W28/b235-244 | `ftell()` return not checked before feeding `*len` — could go negative → huge size_t on cast. |
| 100 | `src/eap_server/eap_server_aka.c:1022` | W25/b205-214 | Unchecked return of `eap_aka_add_id_msg()` — low severity, OOM-only. |
| 101 | `src/crypto/random.c:125` | W25/b205-214 | `hash_ptr=(u32*)hash` on a `u8[20]` stack array then `hash_ptr[4]` deref — alignment/UB risk. |
| 102 | `src/pcsc/pcsc_funcs.c:557` | W26/b215-224 | Unbounded `os_malloc(len)` sized from a first `SCardListReaders()` call with no sanity check. |
| 103 | `src/ap/ieee802_11_defs.h:1345` | W24/b195-204 | `TX_BF_CAP_CALIBRATION_MASK` macro has an unbalanced paren (5 opens/4 closes) — confirmed dead/unused typo via grep. |
| 104 | `examples/browser.c:55/:67` (GTK demo code) | W24/b195-204 | Unchecked/truncating `snprintf` building window title from unbounded webpage title; unguarded `atoi()` parsing OSU trigger URL. |
| 105 | `src/tls/tlsv1_client_write.c` (`tlsv1_key_x_rsa`) | W30/b255-264 | Lacks the explicit end-`*pos` sufficiency check its DH sibling has before sizing an RSA-encryption output buffer. |
| 106 | `src/fst/fst_session.c` (CONFIG_FST_TEST-only `get_group_fill_session`) | W21/b165-174 | `dl_list` wraparound can produce a bogus non-NULL `old_iface` pointer when a group has only one interface, bypassing the NULL check. |
| 107 | Windows CryptoAPI RSA glue | Mini-wave | Unchecked `BN_dup` — out of scope for the Linux oracle. |
| 108 | `src/tls/tls_openssl.c` (`eap_wsc.c`) / `wps_upnp.c eth_get:900` — sqc caught this correctly (TP) | W25/b205-214 | Genuine UAF, `os_free(buf)` then `buf+len` arithmetic, in a FreeBSD/Apple-only `#if` block. |
| 109 | `wpa_supplicant/eap_teap_common.c` etc. — various single-instance leaks/off-by-ones from waves 32-33 | W32/W33 | See individual wave sections in todo-sqlite-cli task 159 for exact citations not preserved above (`l2_packet_pcap.c`, `robust_av.c`, `driver_wired.c` covered as items 91-93). |

---

## Summary counts by severity class

| Class | Count |
|---|---|
| Memory-safety: OOB read (attacker/wire-reachable) | 9 |
| Memory-safety: OOB write / overflow (attacker/wire-reachable) | 2 |
| Memory-safety: OOB read/write (local IPC / config / non-wire) | ~9 |
| Invalid free | 2 |
| Double-free / UAF | 1 (+1 previously-correct TP noted) |
| NULL dereference | 16 |
| Broken error contract / logic bug | 12 |
| Signal-handler safety (SIG30-C) | 1 |
| Sensitive-data hygiene (unzeroed secrets) | 4 |
| Resource/memory leak | ~26 |
| Crypto correctness bug | 1 |
| Lower-severity / dead-code / out-of-scope | ~15 |
| **Total distinct real hostap defects logged** | **~40+ headline bugs, ~109 entries total including minor/duplicate-class items** |

Note: a handful of entries above are cases where **sqc's own findings were confirmed correct** (real bugs it caught, not misses) — retained here because the notes explicitly flagged them as security-relevant validation points, not because they're FNs. These are marked inline. Everything else is a genuine false negative — a real hostap defect sqc's current rule set did not surface.
