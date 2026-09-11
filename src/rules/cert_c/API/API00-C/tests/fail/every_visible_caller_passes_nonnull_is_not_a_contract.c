/*
 * Rule: API00-C
 * Source: custom
 * Status: FAIL - SHOULD trigger API00-C violation
 * Description: A public function that dereferences its pointer parameter
 * without validating it is reported even when every call site the scan can
 * see hands it a provably non-null argument.
 *
 * `wpa_config_set_ssid` has external linkage. The only caller in this file
 * passes `&ssid`, so the prescan's call-site vote for parameter 0 is NotNull.
 * A prior version of the rule took that vote as a reason to stay silent. It
 * is not one: the vote is an observation over the callers currently in the
 * scan set, and an exported function can be called from a translation unit
 * the scan never saw, from another library, or from code not yet written.
 * Under the project's suppression rule (silence only what the tool can
 * PROVE innocuous) an inferred "everyone I can see is careful" is not a
 * proof, and it silenced ~314 confirmed true positives on the corpus.
 *
 * The provable caller-side fact -- every call site is visible because the
 * function is `static` -- describes exactly the functions this rule does not
 * judge, so no linkage gate rescues the shortcut either.
 */

struct wpa_ssid {
    int id;
    char name[32];
};

int wpa_config_set_ssid(struct wpa_ssid *ssid, int id)
{
    ssid->id = id;
    return 0;
}

int wpa_config_init(void)
{
    struct wpa_ssid ssid;
    return wpa_config_set_ssid(&ssid, 1);
}
