/*
 * Rule: ARR30-C
 * Source: task 1278 (hostap src/drivers/driver_ndis.c:2072,
 *         src/radius/radius_das.c:113, wpa_supplicant/config_winreg.c:345)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: the clamp idiom. `if (len >= sizeof(name)) len = sizeof(name) - 1;`
 *         leaves `len < sizeof(name)` on BOTH paths: the guard's false side
 *         proves it directly, and the true side assigns a value below the
 *         same bound. The guard body does not leave, so no branch is known at
 *         the access -- what is known is that the only statement in the body
 *         is that one assignment. The literal form `namelen = 255 - 1` also
 *         pins a second defect: the constant-index resolver's regex read that
 *         as `namelen = 255` and reported `name[namelen]` as a constant index
 *         one past the end. The indices are locals fed by a call, not
 *         parameters: a parameter index takes a different, older path.
 */

#include <string.h>

unsigned int rd_len(void);

void device_name(const char *pos)
{
    char name[256];
    unsigned int j;
    unsigned int len = rd_len();

    if (len >= sizeof(name))
        len = sizeof(name) - 1;
    for (j = 0; j < len; j++)
        name[j] = pos[j];
    name[len] = '\0';
}

void station_id(const unsigned char *buf)
{
    char tmp[100];
    size_t len = rd_len();

    if (len >= sizeof(tmp)) {
        len = sizeof(tmp) - 1;
    }
    memcpy(tmp, buf, len);
    tmp[len] = '\0';
}

void registry_name(const char *src)
{
    char name[255];
    unsigned int namelen = (unsigned int)strlen(src);

    if (namelen >= 255)
        namelen = 255 - 1;
    memcpy(name, src, namelen);
    name[namelen] = '\0';
}
