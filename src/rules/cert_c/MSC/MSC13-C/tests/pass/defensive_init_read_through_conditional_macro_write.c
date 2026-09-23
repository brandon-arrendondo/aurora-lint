/*
 * Rule: MSC13-C
 * Source: mbedtls library/psa_crypto.c
 * Status: PASS - No violation
 *
 * The macro writes `status` only inside its `if` body, so on the
 * fallthrough path the initial PSA_SUCCESS survives to `return status`
 * when the subsystem is already initialised. A write governed by a
 * condition inside a macro is not a kill on every path through it.
 */

#define PSA_SUCCESS 0
#define PSA_ERROR_SERVICE_FAILURE -144

#define THREADING_CHK_GOTO_EXIT(f)                       \
    do {                                                 \
        if ((f) != 0) {                                  \
            status = PSA_ERROR_SERVICE_FAILURE;          \
            goto exit;                                   \
        }                                                \
    } while (0)

int mutex_lock(void);
int mutex_unlock(void);
int init_drivers(void);
extern int initialized;

int init_subsystem(void)
{
    int status = PSA_SUCCESS;

    THREADING_CHK_GOTO_EXIT(mutex_lock());
    if (!initialized) {
        status = init_drivers();
        initialized = 1;
    }
    THREADING_CHK_GOTO_EXIT(mutex_unlock());

exit:
    return status;
}
