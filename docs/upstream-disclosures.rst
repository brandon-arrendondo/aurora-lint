Upstream Disclosures
=====================

Both of aurora-lint's real-world benchmark projects that have gone through a
full file-at-a-time adjudication audit (see
:doc:`testing-methodology`) have produced genuine defects, reported to each
project's maintainers. As of 2026-09-14, **27 of 27 disclosed defects across
the two audits have been confirmed and fixed upstream** — nine in SQLite,
eighteen in hostapd/wpa_supplicant (eight from the initial 2026-08-25
disclosure, ten more from a 2026-09-10 follow-up — see
`Second hostap disclosure`_ below).

A finding being disclosed here does not always mean aurora-lint detected it.
Adjudicating a run means a reviewer reads every flagged site against source
to label it TP/FP; that close reading regularly surfaces genuine defects the
tool's rule set missed entirely. Those are false negatives for aurora-lint,
not detections, and each table below marks its source honestly rather than
crediting the tool for what a human reviewer found.

Methodology
-----------

Every defect below came out of the same process described in full in
:doc:`testing-methodology`: a file-at-a-time real-world audit, not a
sampled spot-check. A reviewer works through every file in scope for the
codebase, adjudicates every aurora-lint finding in that file TP/FP against
source, and — because that means reading the surrounding function rather
than just the flagged line — logs any genuine defect noticed along the way,
whether or not a rule flagged it. That is why most of the disclosed items
below are audit read-throughs rather than tool detections: the read-through
is a structural side effect of doing adjudication file-at-a-time instead of
finding-at-a-time.

Two things this audit discipline is not:

- **Not a Juliet-style synthetic benchmark.** These are production
  codebases with no injected ground truth; every TP/FP label and every
  audit-found defect is a human judgment call against real source, recorded
  in the project's own ``data/precision_audit/<project>/`` directory.
- **Not the sole source of official precision/recall figures.** Those come
  from the persistent ``ground_truth`` oracle keyed on
  ``(project, commit, file, line, rule)`` — see :doc:`testing-methodology`
  and, for how a rule change is re-adjudicated before its precision is
  cited, the project's benchmark-workflow documentation. Disclosure status
  here and precision/recall status there are tracked separately and can
  move independently: a defect can be disclosed and fixed long before (or
  after) the finding that surfaced it is folded into an official precision
  number.

Before any item below was filed to a maintainer, it was re-verified against
current upstream mainline — not just cited at the audit's original pinned
commit — to avoid disclosing something already fixed. hostap's audit found
and excluded one such case (item 15 below) this way.

SQLite
------

Nine defects found while auditing SQLite (220 files at a pinned commit) were
reported upstream. **The SQLite team confirmed and fixed all nine, most the
same day they were filed.**

.. list-table::
   :header-rows: 1
   :widths: 22 45 15 18

   * - Site
     - Defect
     - Source
     - Report
   * - ``src/os_kv.c`` — ``kvvfsDecode()``
     - Heap buffer overflow: the hex-pair decode branch writes without the
       bounds check its sibling branch has (check-in ``732c8f81b5``)
     - Audit read-through (false negative — aurora-lint does not flag this site)
     - `afbc56be7b <https://sqlite.org/bugs/forumpost/afbc56be7b>`__
   * - ``ext/fts5/fts5_index.c`` — ``fts5SegmentSize()``
     - Signed integer overflow on page numbers decoded from an on-disk
       record with no upper bound validated (check-in ``c97a940ceb``)
     - aurora-lint finding (INT32-C)
     - `2026-08-17 <https://sqlite.org/bugs/info/2026-08-17T20:07:33Z>`__
   * - ``ext/fts5/fts5_index.c`` — ``fts5TestUtf8()``
     - UTF-8 validator advances 3 bytes through a 4-byte sequence, so every
       valid astral-plane character is rejected (check-in ``ac094ec69b``)
     - aurora-lint finding (MSC12-C)
     - `b02657db71 <https://sqlite.org/bugs/forumpost/b02657db71>`__
   * - ``ext/session/changeset.c``
     - ``sqlite3_mprintf()`` result passed to libc ``printf``'s ``%s``,
       bypassing SQLite's own NULL-safe ``mprintf`` — NULL dereference
       under allocation failure
     - aurora-lint finding (EXP34-C)
     - `f20ea456ac <https://sqlite.org/bugs/forumpost/f20ea456ac>`__
   * - ``expert.c``
     - Same defect
     - aurora-lint finding (EXP34-C)
     - `c06a3c0d3f <https://sqlite.org/bugs/forumpost/c06a3c0d3f>`__
   * - ``amatch.c``
     - Same defect
     - aurora-lint finding (EXP34-C)
     - `20d89d613b <https://sqlite.org/bugs/forumpost/20d89d613b>`__
   * - ``sqlite3_stdio.c``
     - Same defect
     - aurora-lint finding (EXP34-C)
     - `ba00fdddda <https://sqlite.org/bugs/forumpost/ba00fdddda>`__
   * - ``fts3.c``
     - Same defect
     - aurora-lint finding (EXP34-C)
     - `9b4276628a <https://sqlite.org/bugs/forumpost/9b4276628a>`__
   * - ``qrf.c``
     - Same defect
     - aurora-lint finding (EXP34-C)
     - `18338dc19d <https://sqlite.org/bugs/forumpost/18338dc19d>`__

Eight of the nine started as an aurora-lint finding — an EXP34-C, INT32-C or
MSC12-C violation that hand-adjudication then confirmed against the source.
The ``kvvfsDecode()`` overflow did not: it was found by the close reading
that reviewing aurora-lint's findings prompted, which makes it a false
negative for the tool. It is listed because it is an honest account of what
the audit produced, not a detection to claim.

All nine came out of the same file-at-a-time audit behind the real-world
precision figures in :doc:`testing-methodology`.

hostap (hostapd / wpa_supplicant)
----------------------------------

The hostap ground-truth audit (736 files, commit ``dcee60436``) surfaced 109
genuine defects the audit log tracked outside of TP/FP labeling — the large
majority found by full file read-throughs during adjudication, not by
aurora-lint's rule set. Of those, the 16 judged attacker-reachable via wire
data (the highest-priority class) were re-verified against current mainline
before any filing. Eight were disclosed privately to Jouni Malinen on
2026-08-25; **he applied all eight patches to hostap mainline on
2026-09-08.** No separate security advisory was published — impact was
judged too small for one, though three of the eight (items 1, 14 and 16
below) were still fixed as defense-in-depth over the maintainer's own doubts
about practical reachability.

.. list-table::
   :header-rows: 1
   :widths: 22 42 12 12 12

   * - Site
     - Defect
     - Source
     - Fixed
     - Commit
   * - ``src/ap/wpa_auth_ft.c`` — ``wpa_ft_process_rdie()``
     - Bounds-checks ``sizeof(*rdie)`` but then writes 2 extra header bytes
       beyond that check (802.11r FT RIC subelement, off-by-2 OOB write)
     - Audit read-through (false negative)
     - 2026-09-08
     - ``fcae90b60``
   * - ``src/common/ieee802_11_common.c`` — ``get_max_nss_capability()``
     - Reads ``optional[0..7]`` of a peer's HE Capabilities element without
       validating the element is long enough to contain those bytes
     - Audit read-through (false negative)
     - 2026-09-08
     - ``895fd5881``
   * - ``src/ap/ieee802_11_eht.c`` — ``hostapd_parse_link_reconf_req_sta_profile()``
     - OOB read when ``sta_info == end``, a valid boundary case the
       preceding length check does not exclude
     - Audit read-through (false negative)
     - 2026-09-08
     - ``652a34915``
   * - ``src/common/ieee802_11_he.c`` — ``copy_sta_he_capab()``
     - Calls ``check_valid_he_mcs()``, which reads unconditionally, before
       the IE-length validation that should gate it
     - Audit read-through (false negative)
     - 2026-09-08
     - ``6cf41afd5``
   * - ``src/ap/drv_callbacks.c`` — ``hostapd_action_rx()`` (NAN USD)
     - Checks only ``plen >= 5`` before reading byte offset 5; needs
       ``>= 6``. Sibling DPP branch in the same function does this correctly
     - Audit read-through (false negative)
     - 2026-09-08
     - ``7ce112433``
   * - ``src/eap_server/eap_server_peap.c`` (SoH vendor-TLV)
     - Checks ``tlv_len < 4`` but reads a 4-byte header that requires
       ``tlv_len >= 8``
     - Audit read-through (false negative)
     - 2026-09-08
     - ``4b5965e61``
   * - ``src/common/nan_de.c`` — ``nan_de_config()`` / ``nan_de_start_new_publish_state()``
     - Rejects ``n_max < n_min`` but not ``n_max == n_min``; equal values
       later cause a mod-by-zero
     - Audit read-through (false negative)
     - 2026-09-08
     - ``ec339318a``
   * - ``src/eap_server/eap_server_ttls.c`` (resumption path)
     - Off-by-one length check (``len < 1`` where the code reads a second
       byte); currently unreachable since the writer always emits ≥2 bytes,
       fixed as defense-in-depth
     - Audit read-through (false negative)
     - 2026-09-08
     - ``95e57025f``

All eight of the disclosed-and-fixed items were audit-discovered false
negatives, not aurora-lint detections — the same honesty distinction drawn
for SQLite's ``kvvfsDecode()`` above. Two further wire-reachable items from
the same audit (``src/eap_server/eap_server.c``'s EAP-Response/Nak length
underflow and ``src/common/nan_de.c``'s bloom-filter mod-by-zero) **were**
genuine aurora-lint (EXP34-C) true positives, are still present upstream,
and remain open: judged not reachable, so never filed. A sixteenth item
(``src/common/sae.c``'s missing NULL guard, also a confirmed EXP34-C true
positive) turned out to already be fixed upstream before the 2026-08-25
filing, per w1.fi advisory 2026-3.

Second hostap disclosure
-------------------------

A follow-up EXP34-C delta-adjudication pass (ground-truth source tag
``task1107_delta_exp34_hostap``) surfaced ten more genuine defects beyond
the first audit — this time the majority (seven) were actual aurora-lint
(EXP34-C) detections rather than audit read-throughs, a useful contrast
with the first batch above. All ten were re-verified against current
mainline before filing, disclosed privately to Jouni Malinen on
2026-09-10, and **all ten (eleven patches — one item split into two
upstream commits, one squashed from three source files into one) were
applied to hostap mainline the very next day, 2026-09-11.**

.. list-table::
   :header-rows: 1
   :widths: 26 42 14 8 10

   * - Site
     - Defect
     - Source
     - Fixed
     - Commit
   * - ``src/ap/wnm_ap.c`` — ``ieee802_11_rx_bss_trans_mgmt_query()``
     - NULL ``%s`` argument: the raw ``hex`` pointer (NULL for an empty
       BSS-TM-candidate list) is passed unconditionally as a ``%s`` arg
       alongside its own ternary-guarded prefix text
     - aurora-lint finding (EXP34-C)
     - 2026-09-11
     - ``9f6ee4d90``
   * - ``wpa_supplicant/ctrl_iface.c`` — ``p2p_ctrl_connect()``
     - NULL pointer deref: the cursor past a bare, syntactically valid PIN
       with no trailing parameters is left NULL, then used unconditionally
       in ``os_strstr(pos, "bstrapmethod=")``; live-reproduced crash via a
       single ``P2P_CONNECT`` ctrl_iface command
     - aurora-lint finding (EXP34-C)
     - 2026-09-11
     - ``f3b1fc3b9``
   * - ``wpa_supplicant/dbus/dbus_new_handlers_p2p.c`` —
       ``wpas_dbus_handler_remove_persistent_group()``
     - Uninitialized stack read: ``dbus_message_get_args()``'s return
       value is never checked, and a type-mismatched D-Bus argument
       leaves the out-parameter never written at all, not merely NULL;
       live-reproduced crash via a malformed ``RemovePersistentGroup``
       D-Bus call
     - aurora-lint finding (EXP34-C)
     - 2026-09-11
     - ``563cfc960``
   * - ``src/crypto/tls_openssl_ocsp.c`` — ``ocsp_find_signer()``
     - Signed/unsigned loop-bound bug: ``sk_X509_num()`` returns ``-1``
       for an empty cert stack, promoted to ``UINT_MAX`` against an
       unsigned loop index — a ~4.3-billion-iteration CPU-exhaustion DoS
       processing an OCSP response with an empty embedded cert list
     - Audit read-through (false negative)
     - 2026-09-11
     - ``db1c8dfce``
   * - ``src/drivers/driver_nl80211_event.c`` — ``nl80211_vendor_event_brcm()``
     - NULL ``%s`` argument: a BRCM vendor netlink event omitting
       ``NL80211_ATTR_VENDOR_DATA`` leaves ``data == NULL``, passed
       unconditionally as a ``%s`` argument; live-confirmed segfault
       under musl libc
     - Audit read-through (false negative)
     - 2026-09-11
     - ``c0b203549``
   * - ``src/eap_server/eap_server_peap.c`` — ``eap_peap_build_phase2_term()``
     - NULL pointer deref: ``eap_server_tls_encrypt()``'s documented
       NULL-return path is checked on one return path but not the
       TLS-1.3-resumed path, which reaches ``wpabuf_len()`` unconditionally
     - aurora-lint finding (EXP34-C)
     - 2026-09-11
     - ``0da59aadc``
   * - ``wpa_supplicant/config_none.c`` + ``config_winreg.c`` —
       ``wpa_config_write()`` (both non-default backends)
     - ``name`` (``wpa_s->confname``) used unconditionally, unlike
       ``config_file.c`` which already guards this exact case; live-
       reproduced literal ``(null)`` in a real daemon's log via
       ``SAVE_CONFIG`` with no ``-c`` config file
     - aurora-lint finding (EXP34-C)
     - 2026-09-11
     - ``f9b9a68c2``, ``536d71c0d``
   * - ``wpa_supplicant/dbus/dbus_new.c`` — ``wpas_dbus_get_group_obj_path()``
     - NULL pointer deref: ``ssid`` (``wpa_s->current_ssid``, legitimately
       NULL for a P2P group owner) dereferenced via
       ``os_memcmp(ssid->ssid, ...)`` once ``dbus_new_path`` is set — the
       ordinary case for any build using the new-style D-Bus API
     - Audit read-through (false negative)
     - 2026-09-11
     - ``47e523bf8``
   * - ``wpa_supplicant/wnm_sta.c`` — ``wnm_scan_process()`` ->
       ``wpa_supplicant_need_to_roam_within_ess()``
     - NULL pointer deref: the post-scan "apply normal roaming rules"
       block dereferences a possibly-NULL ``bss`` candidate, unlike the
       sibling ``pre_scan_check`` branch a few lines above which already
       guards it
     - aurora-lint finding (EXP34-C)
     - 2026-09-11
     - ``e341c11d9``
   * - ``src/utils/browser-{android,system,wpadebug}.c`` (3 files) —
       ``http_req()``
     - NULL pointer deref: ``url`` used unconditionally in raw
       ``os_strcmp()``/``os_strncmp()`` calls — no NULL tolerance on any
       libc; live-reproduced SIGSEGV of the HS2.0 OSU loopback HTTP
       server via a single malformed TCP connection
     - aurora-lint finding (EXP34-C)
     - 2026-09-11
     - ``208c56a03``

Seven of the ten items were genuine aurora-lint EXP34-C detections,
confirmed by hand against source before filing — the opposite mix from
the first batch, where the tool's rule set had missed every item. Three
(the OCSP signed/unsigned loop bound, the BRCM vendor-event NULL ``%s``,
and the P2P group ``ssid`` NULL deref) were audit read-throughs, same
honesty distinction as elsewhere in this document. This obsolete-Passpoint
HS2.0 OSU functionality (item 10) and the low-severity ``%s``-with-NULL
class the maintainer judged non-reachable in some cases were still fixed
by Jouni for repository hygiene, in his own words: "those might as well be
addressed even if there is no real impact at the moment."

Combined total
--------------

27 defects disclosed across the two audits, 27 fixed upstream — SQLite's
nine the same day (most of them) or within days, hostap/wpa_supplicant's
first eight within two weeks and the second ten the very next day, all by
the project's original author and lead maintainer, Jouni Malinen.
