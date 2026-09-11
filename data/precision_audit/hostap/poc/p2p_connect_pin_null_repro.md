# Reproduced: P2P_CONNECT PIN-keypad NULL deref (wpa_supplicant/ctrl_iface.c:6596)

## Command
```
$ wpa_cli p2p_connect 02:00:00:00:00:11 12345670
```
(Any well-formed MAC + a bare 4- or 8-digit PIN, no trailing space/params.
`addr` need not correspond to a real/known P2P peer -- only `hwaddr_aton()`
syntax-checks it before the PIN-parsing code runs.)

## Build
Pinned checkout `~/toolchain/hostap` @ `dcee60436390dd34731560657c4257c3b4c839a6`,
`wpa_supplicant/defconfig` + `-fsanitize=address,undefined -fno-omit-frame-pointer
-g -O0`, `CONFIG_CTRL_IFACE_DBUS_NEW=y CONFIG_P2P=y CONFIG_WPS=y`. Run against a
`mac80211_hwsim` simulated radio (`modprobe mac80211_hwsim radios=1`), single
interface, `-Dnl80211 -iwlan0`, `ASAN_OPTIONS=detect_leaks=0`.

## Result
```
ctrl_iface.c:6596:9: runtime error: null pointer passed as argument 1, which is declared to never be null
AddressSanitizer:DEADLYSIGNAL
==466093==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
==466093==The signal is caused by a READ memory access.
==466093==Hint: address points to the zero page.
    #0 __strstr_sse2_unaligned
    #3 p2p_ctrl_connect /wpa_supplicant/ctrl_iface.c:6596
    #4 wpa_supplicant_ctrl_iface_process /wpa_supplicant/ctrl_iface.c:13531
    #5 wpa_supplicant_ctrl_iface_receive /wpa_supplicant/ctrl_iface_unix.c:184
```
Full trace: `p2p_connect_pin_null_asan.txt`.

## Root cause
`p2p_ctrl_connect()`, PIN-keypad branch:
```c
pin = pos;
pos = os_strchr(pin, ' ');       /* NULL if no trailing space */
wps_method = WPS_PIN_KEYPAD;
if (pos) {
    *pos++ = '\0';
    if (os_strncmp(pos, "display", 7) == 0)
        wps_method = WPS_PIN_DISPLAY;
}
if (!wps_pin_str_valid(pin)) {   /* validates pin only, not pos */
    os_memcpy(buf, "FAIL-INVALID-PIN\n", 17);
    return 17;
}
...
pos2 = os_strstr(pos, "bstrapmethod=");   /* line 6596 -- pos may be NULL here */
```
`wps_pin_str_valid()` (`src/wps/wps_common.c:256`) only checks that `pin` is a
bare 4- or 8-digit numeric string -- it never looks at `pos`. A bare valid PIN
with nothing after it (the exact CLI usage the debug-log usage string
documents: `<addr> <"pbc"|"pin"|"pair"|PIN> [label|display|keypad|p2ps] ...`,
where the trailing options are all OPTIONAL) leaves `pos == NULL`, which then
reaches an unconditional `os_strstr(pos, "bstrapmethod=")` with no guard.

## Reachability
Local `wpa_cli`/ctrl_iface command, unauthenticated at the socket level beyond
normal ctrl_iface access control (group-restricted Unix socket by default, or
whatever wraps it -- e.g. a management daemon/UI that forwards user-supplied
PIN strings). No P2P peer discovery, no prior state, no crafted wire frame
needed -- a single local command with a syntactically-valid short PIN.
